package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/Masterminds/sprig/v3"
)

var his []time.Time

func admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/html")

	yourip := r.Header.Get("X-Forwarded-For")

	err := r.ParseForm()
	isipv6 := net.ParseIP(yourip).To4() == nil
	iptablesCmd := "iptables"
	if isipv6 {
		iptablesCmd = "ip6tables"
	}

	var action string
	var sshacceptfound bool
	var sshallowlist []string
	setsshacceptfound := func() {
		sshacceptfound = false
		sshallowlist = execCommandGetLines(r.Context(), 1000, "/tmp",
			iptablesCmd, "-L", "acceptlist", "-nv")
		for i := range sshallowlist {
			if strings.Contains(sshallowlist[i], yourip) {
				sshacceptfound = true
			}
		}
	}
	setsshacceptfound()
	if r.Form.Has("removeyouripfromaccept") {
		if !sshacceptfound {
			action = "Remove command result: Your IP not found in accept list. "
		}
		actionlines := execCommandGetLines(r.Context(), 1000, "/tmp",
			iptablesCmd, "-D", "acceptlist", "-s", yourip, "-j", "REJECT")
		action = action + strings.Join(actionlines, "\n")
		setsshacceptfound()
	}
	if r.Form.Has("addyouriptoaccept") {
		if sshacceptfound {
			action = "Add command result: Your IP already found in accept list. "
		} else {
			actionlines := execCommandGetLines(r.Context(), 1000, "/tmp",
				iptablesCmd, "-A", "acceptlist", "-s", yourip, "-j", "REJECT")
			action = action + strings.Join(actionlines, "\n")
			setsshacceptfound()
		}
	}

	data := struct {
		YourIP      string
		RemoteAddr  string
		QueryParams string
		Headers     http.Header

		IPTAcceptlist  string
		His            []time.Time
		Cls            []string
		IPV6           bool
		SSHAcceptFound bool
		SSHAcceptList  []string
		Error          error
		Action         string
	}{
		RemoteAddr:  r.RemoteAddr,
		YourIP:      yourip,
		QueryParams: fmt.Sprintf("%#v", r.URL.Query()),
		Headers:     r.Header,
		Cls:         cls,
		// If it can't be turned in to a 4, then it is ipv6.
		IPV6:           isipv6,
		SSHAcceptFound: sshacceptfound,
		SSHAcceptList:  sshallowlist,
		Error:          err,
		Action:         action,
	}
	tpl, err := template.New("").Funcs(sprig.FuncMap()).ParseFiles("admin.html")
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, `<html><head></head><body>error parsing template: 
		%s
		</body></html>
		`, err)
		return
	}

	if r.URL.Query().Has("hi") {
		his = append(his, time.Now())
	}
	data.His = his

	ipt, err := exec.CommandContext(r.Context(),
		"iptables", "-L", "acceptlist", "-vn").CombinedOutput()
	if err != nil {
		ipt = []byte(fmt.Sprintf("error executing iptables: %v", err))
	}
	ipt6, err := exec.CommandContext(r.Context(),
		"ip6tables", "-L", "acceptlist", "-vn").CombinedOutput()
	if err != nil {
		ipt = append(ipt, []byte(fmt.Sprintf("error executing iptables: %v", err))...)
	}
	ipt = append(ipt, ipt6...)
	data.IPTAcceptlist = string(ipt)

	err = tpl.ExecuteTemplate(w, "admin.html", data)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, `<html><head></head><body>error executing template: 
		%s
		</body></html>
		`, err)
		return
	}
}
