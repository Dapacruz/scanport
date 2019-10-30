package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

type arrayFlag []string

func (i *arrayFlag) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *arrayFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var hosts arrayFlag
	var ports arrayFlag
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	flag.Var(&hosts, "host", "Hostname or IP address of host to scan. Flag can be specified more than once.")
	flag.Var(&ports, "p", "TCP/UDP port to scan. Flag can be specified more than once.")
	protocol := flag.String("proto", "tcp", "Protocol to scan (TCP/UDP).")
	t := flag.String("t", "1", "Connection timeout in seconds.")

	flag.Parse()
	// Ensure at least one host and port are defined, exit and display usage
	if len(hosts) == 0 || len(ports) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	timeout, _ := time.ParseDuration(*t + "s")

	for _, h := range hosts {
		addr, hostname := resolveHost(h)

		for _, p := range ports {
			r := scanPort(addr, p, strings.ToLower(*protocol), timeout)
			if r == "open" {
				green.Printf("%v (%v) ==> %v/%v is %v\n", addr, hostname, strings.ToUpper(*protocol), p, r)
			} else {
				red.Printf("%v (%v) ==> %v/%v is %v\n", addr, hostname, strings.ToUpper(*protocol), p, r)
			}
		}
	}
}

func resolveHost(host string) (addr, hostname string) {
	if isIPAddress(host) {
		addr = host
		r, err := net.LookupAddr(addr)
		if err == nil {
			// Use first returned hostname and trim trailing period
			hostname = r[0][:len(r[0])-1]
		} else {
			hostname = ""
		}
	} else {
		hostname = host
		r, err := net.LookupIP(hostname)
		if err != nil {
			fmt.Printf("Unable to resolve host: %v\n", hostname)
			os.Exit(1)
		} else {
			// Use first returned address
			addr = r[0].String()
		}
	}
	return addr, hostname
}

func isIPAddress(addr string) bool {
	re := regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
	return re.MatchString(addr)
}

func scanPort(ip string, port string, protocol string, timeout time.Duration) string {
	// TODO: Implment UDP port testing

	target := fmt.Sprintf("%s:%s", ip, port)
	conn, err := net.DialTimeout(protocol, target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			scanPort(ip, port, protocol, timeout)
		}
		return "closed"
	}

	conn.Close()
	return "open"
}
