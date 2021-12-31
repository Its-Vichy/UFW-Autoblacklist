package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"os/exec"
	"regexp"
	"time"
)

var (
	found_address []string
	blacklisted   []string
	max_conn      = 5
)

func juge_spam(match string, list []string) bool {
	count := 0

	for _, item := range list {
		if match == item {
			count += 1
		}
	}

	if count >= max_conn {
		blacklisted = append(blacklisted, match)
		return true
	} else {
		return false
	}
}

func is_blacklisted(match string) bool {
	for _, item := range blacklisted {
		if match == item {
			return true
		}
	}

	return false
}

func blacklist(host string, text string) {
	for _, addr := range regexp.MustCompile(`((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`).FindAllString(text, -1) {
		if addr != host || !is_blacklisted(addr) {
			if juge_spam(addr, found_address) {
				exec.Command("bash", "-c", fmt.Sprintf("iptables -I INPUT -s %s -j DROP", addr)).Run()
				fmt.Printf("> Blacklist address --> %s\n", addr)
				return
			}

			found_address = append(found_address, addr)
		}
	}
}

func resolve_host() string {
	res, _ := http.Get("https://api.ipify.org")
	addr, _ := ioutil.ReadAll(res.Body)

	return string(addr)
}

func main() {
	fmt.Println("|*> UFW-Firewall - github.com/its-vichy")
	host := resolve_host()

	for {
		data := bufio.NewReader(os.Stdin)
		scanner := bufio.NewScanner(data)

		for scanner.Scan() {
			go blacklist(host, scanner.Text())
			time.Sleep(1 * time.Second)
		}
	}
}
