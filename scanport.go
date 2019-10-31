package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

type arrayFlagString []string

func (i *arrayFlagString) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *arrayFlagString) Set(value string) error {
	if len(*i) > 0 {
		return errors.New("interval flag already set")
	}
	for _, t := range strings.Split(value, ",") {
		t = strings.Trim(t, " ")
		*i = append(*i, t)
	}
	return nil
}

func main() {
	var hosts arrayFlagString
	var tcpPorts arrayFlagString
	var udpPorts arrayFlagString

	// Create objects to colorize stdout
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	flag.Var(&hosts, "host", "Comma-separated list of hostnames and/or IP addresses of host to scan")
	flag.Var(&tcpPorts, "tp", "Comma-separated list of TCP ports to scan")
	flag.Var(&udpPorts, "up", "Comma-separated list of UDP ports to scan")
	t := flag.String("t", "1", "Connection timeout in seconds")

	flag.Parse()

	// Ensure at least one host and port are defined, otherwise exit and display usage
	if len(hosts) == 0 || (len(tcpPorts) == 0 && len(udpPorts) == 0) {
		flag.Usage()
		os.Exit(1)
	}

	timeout, _ := time.ParseDuration(*t + "s")

	for _, h := range hosts {
		addr, hostname := resolveHost(h)

		for _, p := range tcpPorts {
			r := scanPort(addr, p, "tcp", timeout)
			if r == "open" {
				green.Printf("%v (%v) ==> TCP/%v is %v\n", addr, hostname, p, r)
			} else {
				red.Printf("%v (%v) ==> TCP/%v is %v\n", addr, hostname, p, r)
			}
		}

		for _, p := range udpPorts {
			r := scanPort(addr, p, "udp", timeout)
			if r == "open" {
				green.Printf("%v (%v) ==> UDP/%v is %v\n", addr, hostname, p, r)
			} else {
				red.Printf("%v (%v) ==> UDP/%v is %v\n", addr, hostname, p, r)
			}
		}
	}
}

func resolveHost(host string) (addr, hostname string) {
	if isIPAddress(host) {
		addr = host
		r, err := net.LookupAddr(addr)
		if err != nil {
			hostname = ""
		} else {
			// Use first returned hostname and trim trailing period
			hostname = r[0][:len(r[0])-1]
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
	// TODO: Implement UDP port testing

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
