package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/gorilla/securecookie"
	sysdwatchdog "github.com/iguanesolutions/go-systemd/v5/notify/watchdog"
	"github.com/jrwren/sadv"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	sessionCookieName = "session"
	tvHostname        = "lgtv.powerpuff"
	// youtubeDLPath can be "youtube-dl" if it is in $PATH.
	//youtubeDLPath = "/home/jrwren/bin/youtube-dl"
	youtubeDLPath = "/home/jrwren/bin/yt-dlp"
)

func main() {
	log.SetFlags(log.Lshortfile)
	// Sure you could use GenerateKey or you could use petname -words=6 😀
	hashKey := []byte("unfocusedly-sporadically-determinedly-inordinately-kind-Nikolas")
	// if block key is nil, then no encryption.
	// var blockKey = []byte("")
	flag.BoolVar(&manageTV, "managetv", false, "manage the TV")
	pp := flag.Bool("proxy", true, "listen using PROXY protocol")
	flag.Parse()
	//	go pinger()
	s = securecookie.New(hashKey, nil)
	r := http.NewServeMux()
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)
	r.HandleFunc("/etv", authnCheck(etv)) // enable TV
	r.HandleFunc("/admin", authnCheck(admin))
	r.HandleFunc("/cl", cl)
	r.HandleFunc("/statusTV", acao(statusTV)) // status TV
	r.HandleFunc("/blockYT", authnCheck(lockNamedFile(blockYT)))
	r.HandleFunc("/enableYT", authnCheck(lockNamedFile(enableYT)))
	r.HandleFunc("/statusYT", acao(statusYT))
	r.HandleFunc("/blockLilly", authnCheck(lockNamedFile(blockLilly)))
	r.HandleFunc("/enableLilly", authnCheck(lockNamedFile(enableLilly)))
	r.HandleFunc("/statusLilly", acao(statusLilly))
	r.HandleFunc("/blockFB", authnCheck(lockNamedFile(blockFB)))
	r.HandleFunc("/enableFB", authnCheck(lockNamedFile(enableFB)))
	r.HandleFunc("/statusFB", acao(statusFB))
	r.HandleFunc("/blockBeacons", authnCheck(lockNamedFile(blockBeacons)))
	r.HandleFunc("/enableBeacons", authnCheck(lockNamedFile(enableBeacons)))
	r.HandleFunc("/statusBeacons", acao(statusBeacons))
	r.HandleFunc("/blockPorn", authnCheck(lockNamedFile(blockPorn)))
	r.HandleFunc("/enablePorn", authnCheck(lockNamedFile(enablePorn)))
	r.HandleFunc("/statusPorn", acao(statusPorn))
	r.HandleFunc("/download", authnCheck(download))
	r.HandleFunc("/play", authnCheck(play))
	r.HandleFunc("/recent", acao(recent))
	r.Handle("/metrics", promhttp.Handler())
	fs, err := fs.Sub(embededHTML, ".")
	if err != nil {
		log.Fatal(err)
	}
	r.Handle("/", http.FileServer(http.FS(fs)))

	watchdog, err := sysdwatchdog.New()
	if err != nil {
		log.Printf("failed to initialize systemd watchdog controller: %v\n", err)
	}

	if watchdog != nil {
		// Then start a watcher worker
		go func() {
			ticker := watchdog.NewTicker()
			defer ticker.Stop()
			for range ticker.C {
				// Check if something wrong, if not send heartbeat
				if healthOK() {
					if err = watchdog.SendHeartbeat(); err != nil {
						log.Printf("failed to send systemd watchdog heartbeat: %v\n", err)
					}
				}
			}
		}()
	}

	go func() {
		caCert, err := ioutil.ReadFile("cert.pem")
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Create the TLS Config with the CA pool and enable Client certificate validation
		tlsConfig := &tls.Config{
			ClientCAs: caCertPool,
			//			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientAuth: tls.VerifyClientCertIfGiven,
		}

		// Create a Server instance to listen on port 8443 with the TLS config
		server := &http.Server{
			Addr:      ":9621",
			TLSConfig: tlsConfig,
			Handler:   compress(NoDateForSystemDHandler(os.Stdout, r)),
		}
		log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
	}()
	switch *pp {
	case false:
		log.Fatal(http.ListenAndServe(":9620",
			compress(NoDateForSystemDHandler(os.Stdout, r))))
	case true:
		server := http.Server{
			Addr:    ":9620",
			Handler: compress(NoDateForSystemDHandler(os.Stdout, r)),
		}
		ln, err := net.Listen("tcp", server.Addr)
		if err != nil {
			log.Fatal(err)
		}
		proxyListener := &proxyproto.Listener{
			Listener:          ln,
			ReadHeaderTimeout: 10 * time.Second,
		}
		defer proxyListener.Close()
		server.Serve(proxyListener)
	}
}

func healthOK() bool {
	resp, err := http.Get("http://localhost:9620")
	if err != nil {
		log.Print("error with health check", err)
		return false
	}
	if resp.StatusCode != 200 {
		log.Print("error with health check not 200", resp.StatusCode)
		return false
	}
	return true
}

// this global means i should extract to a server type soon.
var (
	namedMu     sync.Mutex
	tvTimer     *time.Timer // Timer for disabling TV
	tvTimerTime time.Time   // Time of expected TV disable.

	// tvPingOn is true if tv is successfully pinged and false if ping fails.
	tvPingOn bool

	manageTV bool

	s *securecookie.SecureCookie
	//go:embed *.html *.js
	embededHTML embed.FS
)

func pinger() {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		log.Print("pinger error listening", err)
	}
	defer c.Close()

	ct := time.Tick(5 * time.Second)
	for range ct {
		err = c.SetDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			log.Print("pinger couldn't set deadline", err)
			continue
		}
		wm := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: 1,
				Data: []byte("etv pinging ya"),
			},
		}
		wb, err := wm.Marshal(nil)
		if err != nil {
			log.Print("pinger error marshaling", err)
			continue
		}
		ip, err := net.LookupIP(tvHostname)
		if err != nil {
			log.Print("pinger could not lookup ip", err)
			continue
		}
		addr := &net.UDPAddr{IP: ip[0]}
		if _, err := c.WriteTo(wb, addr); err != nil {
			tvPingOn = false
			log.Print("pinger error writing", err)
			continue
		}

		rb := make([]byte, 1500)
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Print("pinger error reading", err)
			}
			if tvPingOn {
				tvPingOn = false
				tvOff()
			}
			continue
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			log.Print("pinger error parsing", err)
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			if peer.String() != addr.String() {
				log.Printf("got reflection from %v expecting %v", peer, addr)
			}
			if !tvPingOn {
				tvPingOn = true
				tvOn()
			}
		default:
			log.Printf("pinger got %+v; want echo reply", rm)
			tvPingOn = false
		}
	}
}

// tvOn is called when the state of the TV changes from Off to On.
func tvOn() {
	now := time.Now()
	// After 6pm, allow TV when it turns off and disable the timer.
	if manageTV && now.Hour() > 18 {
		log.Print("tv turned on after 6pm, enabling")
		enableTV(nil)
		tvTimer.Stop()
	}
}

// tvOff is called when the state of the TV changes from On to Off
func tvOff() {
	now := time.Now()
	if manageTV && (now.Hour() > 23 || now.Hour() < 6) {
		log.Print("tv turned off after 11pm, disabling")
		blockHosts(tvHostname, "kodi.powerpuff")
	}
}

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

func authnCheck(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
				http.StatusMethodNotAllowed)
			return
		}
		acao(emptyHandlerFunc())(w, r)
		// If a cert auth (mtls) was used, then no session cookie required.
		if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
			// I feel like I should log an auth name here.
			// Cert CN or something?
			f(w, r)
			return
		}
		_, err := getSecureSessionCookieValue(r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden),
				http.StatusForbidden)
			return
		}
		// At this point, don't even care what the cookie value is, since we
		// aren't using the authenticated user for anything. Just accept that
		// it is secure.
		f(w, r)
	})
}

var cls []string

func cl(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "OK")
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
	}
	cls = append(cls, string(b))
	r.Body.Close()
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
		http.Error(w, "authentication failed", http.StatusForbidden)
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
		Name:  sessionCookieName,
		Value: cvalue,
		// Expires is deprecated. Use MaxAge.
		// Expires:  time.Now().Add(365 * 24 * time.Hour),
		MaxAge:   int((time.Hour * 365 * 24).Seconds()),
		HttpOnly: true,
	}
	http.SetCookie(w, c)
	log.Print(username, "successfully authenticated")
	redir := r.Form.Get("redirect")
	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
}

func statusTV(w http.ResponseWriter, r *http.Request) {
	out, err := exec.CommandContext(r.Context(),
		"iptables", "-L", "INPUT").CombinedOutput()
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
		if strings.Contains(l, tvHostname) {
			respj["status"] = "TV(amazon) and Kodi are currently disabled"
		}
	}
	respj["tvpstatus"] = "The TV is off."
	if tvPingOn {
		respj["tvpstatus"] = "The TV is on."
	}
	// State could be wonky on first run if tvTimeTime IsZero AND tv is enabled.
	// if tvTimerTime.IsZero() && strings.HasSuffix(respj["status"], "enabled") {
	// 	tvTimerTime = time.Now().Add(time.Hour)
	// 	tvTimer = time.AfterFunc(time.Until(tvTimerTime), func() {
	// 		blockHosts(tvHostname, "kodi.powerpuff")
	// 	})
	// }
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
	if !manageTV {
		respj := make(map[string]string)
		respj["message"] = "TV and Kodi management are disabled"
		err := json.NewEncoder(w).Encode(respj)
		if err != nil {
			log.Print(err)
			return
		}
		return
	}
	if !tvTimerTime.IsZero() {
		// TV is already enabled, just add time.
		tvTimerTime = tvTimerTime.Add(15 * time.Minute)
		if !tvTimer.Stop() {
			<-tvTimer.C
		}
		tvTimer = time.AfterFunc(time.Until(tvTimerTime), func() {
			blockHosts(tvHostname, "kodi.powerpuff")
			tvTimerTime = time.Time{} // Zero it until the next enable.
		})
	} else {
		enableTV(w)
		tvTimerTime = time.Now().Add(time.Hour)
		tvTimer = time.AfterFunc(time.Until(tvTimerTime), func() {
			blockHosts(tvHostname, "kodi.powerpuff")
			tvTimerTime = time.Time{} // Zero it until the next enable.
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

func enableTV(w http.ResponseWriter) {
	out, err := exec.Command("iptables", "-D", "INPUT", "-s", tvHostname,
		"-j", "DROP").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		if w != nil {
			http.Error(w, "could not run iptables for TV", http.StatusServiceUnavailable)
		}
		return
	}
	out, err = exec.Command("iptables", "-D", "INPUT", "-s", "kodi.powerpuff",
		"-j", "DROP").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		if w != nil {
			http.Error(w, "could not run iptables for kodi", http.StatusServiceUnavailable)
		}
		return
	}
}

func blockHosts(hosts ...string) {
	for _, host := range hosts {
		out, err := exec.Command("iptables", "-I", "INPUT", "9", "-s", host,
			"-j", "DROP").CombinedOutput()
		if err != nil {
			log.Print(err, string(out))
		}
	}
}

func unblockHosts(hosts ...string) {
	for _, host := range hosts {
		out, err := exec.Command("iptables", "-D", "INPUT", "-s", host,
			"-j", "DROP").CombinedOutput()
		if err != nil {
			log.Print(err, string(out))
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

func statusLilly(w http.ResponseWriter, r *http.Request) {
	out, err := exec.CommandContext(r.Context(),
		"iptables", "-L", "INPUT").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		http.Error(w, "could not run iptables for TV", http.StatusServiceUnavailable)
		return
	}
	status := "Lilly's Phone is currently enabled"
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "lilly-iphone.powerpuff") {
			status = "Lilly's Phone is currently disabled"
		}
	}
	writeStatus(w, status)
}

func blockLilly(w http.ResponseWriter, r *http.Request) {
	blockHosts("lilly-iphone.powerpuff")
	blockHosts("lilly-iphone2.powerpuff")
	disableMetric.WithLabelValues("Lilly").Add(1)
}

func enableLilly(w http.ResponseWriter, r *http.Request) {
	unblockHosts("lilly-iphone.powerpuff")
	unblockHosts("lilly-iphone2.powerpuff")
	enableMetric.WithLabelValues("Lilly").Add(1)
}

func blockYT(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "YouTube")
	disableMetric.WithLabelValues("youtube").Add(1)
}

func blockFB(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "Facebook")
	disableMetric.WithLabelValues("facebook").Add(1)
}

func blockBeacons(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "Beacons")
	disableMetric.WithLabelValues("beacons").Add(1)
}

func blockPorn(w http.ResponseWriter, r *http.Request) {
	blockX(w, r, "Porn")
	disableMetric.WithLabelValues("porn").Add(1)
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
	enableMetric.WithLabelValues("youtube").Add(1)
}

func enableFB(w http.ResponseWriter, r *http.Request) {
	enableX(w, r, "Facebook")
	enableMetric.WithLabelValues("facebook").Add(1)
}

func enableBeacons(w http.ResponseWriter, r *http.Request) {
	enableX(w, r, "Beacons")
	enableMetric.WithLabelValues("beacons").Add(1)
}

func statusBeacons(w http.ResponseWriter, r *http.Request) {
	statusX(w, r, "Beacons")
}

func enablePorn(w http.ResponseWriter, r *http.Request) {
	enableX(w, r, "Porn")
	enableMetric.WithLabelValues("porn").Add(1)
}

func statusPorn(w http.ResponseWriter, r *http.Request) {
	statusX(w, r, "Porn")
}

func enableX(w http.ResponseWriter, r *http.Request, key string) {
	editX(w, r, key, false, "Enabled!")
}

func statusFB(w http.ResponseWriter, r *http.Request) {
	// w.Header().Add("Access-Control-Allow-Origin", "http://delays.powerpuff")
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
	writeStatus(w, status)
}

func writeStatus(w io.Writer, status string) {
	respj := make(map[string]string)
	respj["status"] = status
	err := json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
	}
}

func play(w http.ResponseWriter, r *http.Request) {
	req := struct {
		URL string
	}{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Print(err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		log.Print("play got empty url")
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.URL, "http") {
		req.URL = "https://" + req.URL
	}
	// TODO: use github.com/mjanser/lgtv
	cmd := exec.CommandContext(r.Context(), "/home/jrwren/lgtv-venv/bin/lgtv", "mytv", "openBrowserAt", req.URL)
	cmd.Env = append(os.Environ(), "HOME=/home/jrwren")
	log.Printf("running %v", cmd)
	if stdoutStderr, err := cmd.CombinedOutput(); err != nil {
		writeStatus(w, err.Error()+" "+string(stdoutStderr))
		log.Print("error sending to TV ", req.URL, err, string(stdoutStderr))
		return
	}
	writeStatus(w, req.URL+" sent to TV")
}

func download(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Target string
		URL    string
	}{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Print(err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	var targetDir string
	switch req.Target {
	case "tv":
		targetDir = "/d/tv/"
	case "movie":
		targetDir = "/d/movies/"
	default:
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
	}
	ctx := r.Context()
	cmd := exec.CommandContext(ctx, youtubeDLPath, req.URL)
	cmd.Dir = targetDir
	if stdoutStderr, err := cmd.CombinedOutput(); err != nil {
		writeStatus(w, err.Error()+" "+string(stdoutStderr))
		log.Print("error downloading ", req.URL, err, string(stdoutStderr))
		return
	}
	writeStatus(w, req.URL+" downloaded")
}

func recent(w http.ResponseWriter, r *http.Request) {
	// TODO: list and stat the files instead of fork/exec
	respj := make(map[string][]string)
	respj["tv"] = tailLatestFiles(r.Context(), "/d/tv", 30)
	respj["movies"] = tailLatestFiles(r.Context(), "/d/movies", 20)
	respj["dns"] = tailquerylog(r.Context(), 100)
	err := json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
	}
}

func tailLatestFiles(ctx context.Context, path string, n int) []string {
	return execCommandGetLines(ctx, n, path, "bash", "-c",
		`find . -maxdepth 1 \( -type d -o -name '*.mp4' -o -name '*.mkv' \)  -a ! -name '.*' -printf "%TF %p\n" | sort`)
}

func execCommandGetLines(ctx context.Context, n int, dir, name string, arg ...string) []string {
	cmd := exec.CommandContext(ctx, name, arg...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []string{string(out), err.Error()}
	}
	lines := strings.Split(string(out), "\n")
	l := len(lines)
	if lines[l-1] == "" {
		lines = lines[:l-1]
		l--
	}
	if l < n {
		n = l
	}
	return lines[l-n : l]
}

func tailquerylog(ctx context.Context, n int) []string {
	//grep -vE '172.17.0.[235]#|192.168.15.(101|156)#|time-ios|apple-dns.net|itunes.apple.com|communities.apple.com' /var/log/named/query | tail -100
	lines := execCommandGetLines(ctx, n, "", "bash", "-c", "grep -vE '172.17.0.[235]#|192.168.15.(101|156)#|time-ios|apple-dns.net|itunes.apple.com|communities.apple.com' /var/log/named/query | tail -100")
	// Cache lookups only per function call.
	dnscache := make(map[string][]string)
	for i := range lines {
		lines[i] = strings.Replace(lines[i], "queries: info: client ", "", 1)
		lines[i] = strings.Replace(lines[i], "view all: query:  ", "", 1)
		h := strings.Index(lines[i], "#")
		ip := lines[i][41:h]
		hn := ""
		nams, ok := dnscache[ip]
		if !ok {
			var err error
			nams, err = net.LookupAddr(ip)
			if err != nil {
				log.Print("err looking up ", ip)
			}
			dnscache[ip] = nams
		}
		if len(nams) > 0 {
			hn = strings.Join(nams, ",")
			// Remove my domain name.
			hn = strings.ReplaceAll(hn, ".powerpuff", "")
			// Remove the trailing dot.
			hn = strings.TrimRight(hn, ".")
		}
		lines[i] = `<span class="date">` + lines[i][0:25] + `</span>` +
			fmt.Sprintf(`<span class="hostname">%20s</span>  `, hn) + lines[i][25+16:]
	}
	return lines
}
