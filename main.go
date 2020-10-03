package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/handlers"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	r := http.NewServeMux()
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
		handlers.CombinedLoggingHandler(os.Stdout, r)))
}

// this global means i should extract to a server type soon.
var namedMu sync.Mutex

func acao(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "http://delays.powerpuff")
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

func doCheck(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
				http.StatusMethodNotAllowed)
			return
		}
		//w.Header().Add("Access-Control-Allow-Origin", "http://delays.powerpuff")
		acao(emptyHandlerFunc())(w, r)
		b := make(map[string]string)
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			log.Print(err)
			return
		}
		if b["key"] != "1234" {
			log.Print("key mismatch", b["key"])
			return
		}
		f(w, r)
	})
}

func statusTV(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("iptables", "-L", "INPUT").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		http.Error(w, "could not run iptables for TV", 503)
		return
	}
	respj := make(map[string]string)
	respj["status"] = "TV(amazon) and Kodi are currently disabled"
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "vizio") {
			respj["status"] = "TV(amazon) and Kodi are currently enabled"
		}
	}
	err = json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
		return
	}
}

func etv(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("iptables", "-D", "INPUT", "-s", "vizio.powerpuff",
		"-j", "DROP").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		http.Error(w, "could not run iptables for TV", 503)
		return
	}
	out, err = exec.Command("iptables", "-D", "INPUT", "-s", "kodi.powerpuff",
		"-j", "DROP").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		http.Error(w, "could not run iptables for kodi", 503)
		return
	}
	go blockIn(time.Hour, "vizio.powerpuff", "kodi.powerpuff")
	respj := make(map[string]string)
	respj["message"] = "TV and Kodi Enabled for 1 hour!"
	err = json.NewEncoder(w).Encode(respj)
	if err != nil {
		log.Print(err)
		return
	}
}

func blockIn(d time.Duration, hosts ...string) {
	time.Sleep(d)
	for _, host := range hosts {
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
	for _, line := range lines {
		if on && !bytes.HasPrefix(line, []byte("//")) && !uncomment {
			io.WriteString(f, "//")
		}
		if bytes.Contains(line, []byte(stop)) {
			on = false
		}
		if on && bytes.HasPrefix(line, []byte("//")) && uncomment {
			line = line[2:]
		}
		f.Write(line)
		io.WriteString(f, "\n")
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
		http.Error(w, "could not edit config file", 503)
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
		http.Error(w, "could not run rndc reload", 503)
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
