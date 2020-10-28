package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/jrwren/sadv"
)

const (
	sessionCookieName = "session"
)

func main() {
	log.SetFlags(log.Lshortfile)
	// Sure you could use GenerateKey or you could use petname -words=6 😀
	var hashKey = []byte("")
	// if block key is nil, then no encryption.
	// var blockKey = []byte("")
	s = securecookie.New(hashKey, nil)
	r := http.NewServeMux()
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)
	r.HandleFunc("/etv", doCheck(etv))        //enable TV
	r.HandleFunc("/statusTV", acao(statusTV)) //status TV
	r.HandleFunc("/blockYT", doCheck(lockNamedFile(blockYT)))
	r.HandleFunc("/enableYT", doCheck(lockNamedFile(enableYT)))
	r.HandleFunc("/statusYT", acao(statusYT))
	r.HandleFunc("/blockFB", doCheck(lockNamedFile(blockFB)))
	r.HandleFunc("/enableFB", doCheck(lockNamedFile(enableFB)))
	r.HandleFunc("/statusFB", acao(statusFB))
	r.HandleFunc("/blockBeacons", doCheck(lockNamedFile(blockBeacons)))
	r.HandleFunc("/enableBeacons", doCheck(lockNamedFile(enableBeacons)))
	r.HandleFunc("/statusBeacons", acao(statusBeacons))

	r.HandleFunc("/blockPorn", doCheck(lockNamedFile(blockPorn)))
	r.HandleFunc("/enablePorn", doCheck(lockNamedFile(enablePorn)))
	r.HandleFunc("/statusPorn", acao(statusPorn))
	log.Fatal(http.ListenAndServe(":9620",
		NoDateForSystemDHandler(os.Stdout, r)))
}

// this global means i should extract to a server type soon.
var namedMu sync.Mutex
var tvTimer *time.Timer   // Timer for disabling TV
var tvTimerTime time.Time // Time of expected TV disable.

var s *securecookie.SecureCookie

func acao(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "http://delays.powerpuff")
		w.Header().Add("Access-Control-Allow-Credentials", "true")
		f(w, r)
	})
}

func lockNamedFile(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		namedMu.Lock()
		defer namedMu.Unlock()
		f(w, r)
	})
}

func emptyHandlerFunc() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
}

func getSecureSessionCookieValue(r *http.Request) (string, error) {
	var value string
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", err
	}
	err = s.Decode(sessionCookieName, cookie.Value, &value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func doCheck(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
				http.StatusMethodNotAllowed)
			return
		}
		acao(emptyHandlerFunc())(w, r)
		_, err := getSecureSessionCookieValue(r)
		if err != nil {
			return
		}
		// At this point, don't even care what the cookie value is, since we
		// aren't using the authenticated user for anything. Just accept that
		// it is secure.
		f(w, r)
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Panicln(err)
	}
	redir := r.Form.Get("redirect")
	if redir == "" {
		redir = "http://delays.powerpuff"
	}
	c := &http.Cookie{
		Name:     "session",
		Value:    "",
		Expires:  time.Now().Add(-1),
		HttpOnly: true,
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
	}
	err := r.ParseForm()
	if err != nil {
		log.Panicln(err)
	}
	username := r.Form.Get("username")
	_, err = sadv.SASLauthdVerifyPassword("",
		username,
		r.Form.Get("password"),
		"", "", "")
	if err != nil {
		_, err = io.WriteString(w, "authentication failed unknown username or invalid password")
		if err != nil {
			log.Println(err)
		}
		return
	}
	i, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		log.Println(err)
		return
	}
	cvalue, err := s.Encode(sessionCookieName, fmt.Sprint(username, ":", i))
	if err != nil {
		log.Panic(err) // Won't happen. right?
	}
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    cvalue,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, r.Form.Get("redirect"), http.StatusTemporaryRedirect)
}

func statusTV(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("iptables", "-L", "INPUT").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		http.Error(w, "could not run iptables for TV", http.StatusServiceUnavailable)
		return
	}
	respj := make(map[string]string)
	respj["status"] = "TV(amazon) and Kodi are currently enabled"
	if !tvTimerTime.IsZero() {
		respj["status"] += " for " + time.Until(tvTimerTime).String()
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "vizio") {
			respj["status"] = "TV(amazon) and Kodi are currently disabled"
		}
	}
	// State could be wonky on first run if tvTimeTime IsZero AND tv is enabled.
	if tvTimerTime.IsZero() && strings.HasSuffix(respj["status"], "enabled") {
		tvTimerTime = time.Now().Add(time.Hour)
		//go blockIn(time.Hour, "vizio.powerpuff", "kodi.powerpuff")
		tvTimer = time.AfterFunc(time.Until(tvTimerTime), func() {
			blockHosts("vizio.powerpuff", "kodi.powerpuff")
		})
	}
	val, err := getSecureSessionCookieValue(r)
	if err == nil {
		s := strings.Split(val, ":")
		username := s[0]
		respj["loginstatus"] = "true"
		respj["username"] = username
	}
	err = json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
		return
	}
}

func etv(w http.ResponseWriter, r *http.Request) {
	if !tvTimerTime.IsZero() {
		// TV is already enabled, just add time.
		tvTimerTime = tvTimerTime.Add(15 * time.Minute)
		if !tvTimer.Stop() {
			<-tvTimer.C
		}
		tvTimer = time.AfterFunc(time.Until(tvTimerTime), func() {
			blockHosts("vizio.powerpuff", "kodi.powerpuff")
		})
	} else {
		out, err := exec.Command("iptables", "-D", "INPUT", "-s", "vizio.powerpuff",
			"-j", "DROP").CombinedOutput()
		if err != nil {
			log.Print(err, string(out))
			http.Error(w, "could not run iptables for TV", http.StatusServiceUnavailable)
			return
		}
		out, err = exec.Command("iptables", "-D", "INPUT", "-s", "kodi.powerpuff",
			"-j", "DROP").CombinedOutput()
		if err != nil {
			log.Print(err, string(out))
			http.Error(w, "could not run iptables for kodi", http.StatusServiceUnavailable)
			return
		}
		tvTimerTime = time.Now().Add(time.Hour)
		//go blockIn(time.Hour, "vizio.powerpuff", "kodi.powerpuff")
		tvTimer = time.AfterFunc(time.Until(tvTimerTime), func() {
			blockHosts("vizio.powerpuff", "kodi.powerpuff")
		})
	}
	respj := make(map[string]string)
	respj["message"] = "TV and Kodi Enabled for " + time.Until(tvTimerTime).String()
	err := json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
		return
	}
}

func blockHosts(hosts ...string) {
	for _, host := range hosts {
		tvTimerTime = time.Time{} // Zero it until the next enable.
		out, err := exec.Command("iptables", "-I", "INPUT", "9", "-s", host,
			"-j", "DROP").CombinedOutput()
		if err != nil {
			log.Print(err, string(out))
			return
		}
	}
}

const namedFile = "/etc/bind/named.conf.local"

func statusYT(w http.ResponseWriter, r *http.Request) {
	statusX(w, r, "YouTube")
}

func commentFileBetween(filename, start, stop string, uncomment bool) error {
	b, err := ioutil.ReadFile(namedFile)
	if err != nil {
		return err
	}
	f, err := os.Create(namedFile)
	if err != nil {
		return err
	}
	lines := bytes.Split(b, []byte("\n"))
	on := false
	for i, line := range lines {
		if on && !bytes.HasPrefix(line, []byte("//")) && !uncomment {
			_, err = io.WriteString(f, "//")
			if err != nil {
				log.Println("ERROR", err)
			}
		}
		if bytes.Contains(line, []byte(stop)) {
			on = false
		}
		if on && bytes.HasPrefix(line, []byte("//")) && uncomment {
			line = line[2:]
		}
		_, err = f.Write(line)
		if err != nil {
			log.Println("ERROR", err)
		}
		// Don't write extra newlines to EOF
		if i != len(lines)-1 {
			_, err = io.WriteString(f, "\n")
			if err != nil {
				log.Println("ERROR", err)
			}
		}
		if bytes.Contains(line, []byte(start)) {
			on = true
		}
	}
	return f.Close()
}

func blockYT(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "YouTube")
}

func blockFB(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "Facebook")
}

func blockBeacons(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "Beacons")
}

func blockPorn(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "Porn")
}

func blockX(w http.ResponseWriter, r *http.Request, key string) {
	editX(w, r, key, true, "Blocked!")
}

func editX(w http.ResponseWriter, r *http.Request, key string, uncomment bool, message string) {
	err := commentFileBetween(namedFile, key, "End", uncomment)
	if err != nil {
		log.Print(err)
		http.Error(w, "could not edit config file", http.StatusServiceUnavailable)
		return
	}

	respj := make(map[string]string)
	respj["message"] = key + " " + message
	err = json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
		return
	}
	out, err := exec.Command("rndc", "reload").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		http.Error(w, "could not run rndc reload", http.StatusServiceUnavailable)
		return
	}
}

func enableYT(w http.ResponseWriter, r *http.Request) {
	enableX(w, r, "YouTube")
}

func enableFB(w http.ResponseWriter, r *http.Request) {
	enableX(w, r, "Facebook")
}

func enableBeacons(w http.ResponseWriter, r *http.Request) {
	enableX(w, r, "Beacons")
}

func statusBeacons(w http.ResponseWriter, r *http.Request) {
	statusX(w, r, "Beacons")
}

func enablePorn(w http.ResponseWriter, r *http.Request) {
	enableX(w, r, "Porn")
}

func statusPorn(w http.ResponseWriter, r *http.Request) {
	statusX(w, r, "Porn")
}

func enableX(w http.ResponseWriter, r *http.Request, key string) {
	editX(w, r, key, false, "Enabled!")
}

func statusFB(w http.ResponseWriter, r *http.Request) {
	//w.Header().Add("Access-Control-Allow-Origin", "http://delays.powerpuff")
	statusX(w, r, "Facebook")
}

func statusX(w http.ResponseWriter, r *http.Request, key string) {
	b, err := ioutil.ReadFile(namedFile)
	if err != nil {
		return
	}
	lines := bytes.Split(b, []byte("\n"))
	on := false
	var status string
	for _, line := range lines {
		if on && !bytes.HasPrefix(line, []byte("//")) {
			status = key + " is currently disabled"
			break
		}
		if on && bytes.HasPrefix(line, []byte("//")) {
			status = key + " is currently enabled"
			break
		}
		if bytes.Contains(line, []byte(key)) {
			on = true
		}
	}
	respj := make(map[string]string)
	respj["status"] = status
	err = json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
		return
	}
}

// NoDateForSystemDHandler is a logging handler which writes most fields of
// a vhost combined logger without the date, because systemd logs a date.
// Normal vhost-combined apache format:
//   %v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i
// Ours:
//   %v:%p %h %u \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i
func NoDateForSystemDHandler(out io.Writer, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		user := "-"
		auth := r.Header.Get("Authorization")

		if strings.HasPrefix(auth, "Basic ") {
			up, err := base64.RawStdEncoding.DecodeString(auth[6:])
			if err == nil {
				ups := strings.SplitN(string(up), ":", 2)
				if len(ups) == 2 {
					user = ups[0]
				}
			}

		}
		if r.URL.User != nil {
			if un := r.URL.User.Username(); un != "" {
				user = un
			}
		}
		t := time.Now() // Not to log the time, but to compute time of request.
		ww := &wrappedResponseWriter{ResponseWriter: w, code: 200}
		referer := r.Header.Get("Referer")
		ua := r.Header.Get("User-Agent")
		h.ServeHTTP(ww, r)
		rt := time.Since(t)

		fmt.Fprintf(out, "%s %s %s \"%s %s %s\" %d %d %q %q %s\n",
			host, r.RemoteAddr, user, r.Method, r.RequestURI,
			r.Proto, ww.code, ww.size, referer, ua, rt)
	})
}

type wrappedResponseWriter struct {
	http.ResponseWriter     // the underlying ResponseWriter.
	code                int // http code returned.
	size                int // size of http response.
}

func (w *wrappedResponseWriter) Write(b []byte) (int, error) {
	s, err := w.ResponseWriter.Write(b)
	w.size += s
	return s, err
}

func (w *wrappedResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
