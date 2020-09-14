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
	"time"

	"github.com/gorilla/handlers"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	r := http.NewServeMux()
	r.HandleFunc("/etv", doCheck(etv)) //enable TV
	r.HandleFunc("/blockYT", doCheck(blockYT))
	r.HandleFunc("/enableYT", doCheck(enableYT))
	r.HandleFunc("/statusYT", statusYT)
	log.Fatal(http.ListenAndServe(":9620", handlers.CombinedLoggingHandler(os.Stdout, r)))
}

func doCheck(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		w.Header().Add("Access-Control-Allow-Origin", "http://delays.powerpuff")
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

func etv(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("iptables", "-D", "INPUT", "-s", "vizio.powerpuff", "-j", "DROP").CombinedOutput()
	if err != nil {
		log.Print(err, string(out))
		http.Error(w, "could not run iptables for TV", 503)
		return
	}
	out, err = exec.Command("iptables", "-D", "INPUT", "-s", "kodi.powerpuff", "-j", "DROP").CombinedOutput()
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
		out, err := exec.Command("iptables", "-I", "INPUT", "9", "-s", host, "-j", "DROP").CombinedOutput()
		if err != nil {
			log.Print(err, string(out))
			return
		}
	}
}

const namedFile = "/etc/bind/named.conf.local"

func statusYT(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "http://delays.powerpuff")
	b, err := ioutil.ReadFile(namedFile)
	if err != nil {
		return
	}
	lines := bytes.Split(b, []byte("\n"))
	on := false
	var status string
	for _, line := range lines {
		if on && !bytes.HasPrefix(line, []byte("//")) {
			status = "YouTube is currently disabled"
			break
		}
		if on && bytes.HasPrefix(line, []byte("//")) {
			status = "YouTube is currently enabled"
			break
		}
		if bytes.Contains(line, []byte("YouTube")) {
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
		if bytes.Contains(line, []byte("End")) {
			on = false
		}
		if on && bytes.HasPrefix(line, []byte("//")) && uncomment {
			line = line[2:]
		}
		f.Write(line)
		io.WriteString(f, "\n")
		if bytes.Contains(line, []byte("YouTube")) {
			on = true
		}
	}
	return f.Close()
}

func blockYT(w http.ResponseWriter, r *http.Request) {
	err := commentFileBetween(namedFile, "YouTube", "End", false)
	if err != nil {
		log.Print(err)
		http.Error(w, "could not edit config file", 503)
		return
	}

	respj := make(map[string]string)
	respj["message"] = "YT BLOCKED!"
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
	err := commentFileBetween(namedFile, "YouTube", "End", true)
	if err != nil {
		log.Print(err)
		http.Error(w, "could not edit config file", 503)
		return
	}

	respj := make(map[string]string)
	respj["message"] = "YT Enabled!"
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
