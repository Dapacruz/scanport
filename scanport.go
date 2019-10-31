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

	fmt.Printf("\nScanning ports ...\n\n")

	for _, h := range hosts {
		addr, hostname := resolveHost(h)

		for _, p := range tcpPorts {
			r := scanTCPPort(addr, p, timeout)
			if r == "open" {
				fmt.Printf("%v (%v) ==> TCP/%v is ", addr, hostname, p)
				green.Println(r)
			} else {
				fmt.Printf("%v (%v) ==> TCP/%v is ", addr, hostname, p)
				red.Println(r)
			}
		}

		for _, p := range udpPorts {
			r := scanUDPPort(addr, p, timeout)
			if r == "open" {
				fmt.Printf("%v (%v) ==> UDP/%v is ", addr, hostname, p)
				green.Println(r)
			} else {
				fmt.Printf("%v (%v) ==> UDP/%v is ", addr, hostname, p)
				red.Println(r)
			}
		}

		fmt.Println()
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

func scanTCPPort(ip string, port string, timeout time.Duration) string {
	target := fmt.Sprintf("%s:%s", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			scanTCPPort(ip, port, timeout)
		}
		return "closed"
	}

	conn.Close()
	return "open"
}

func scanUDPPort(ip string, port string, timeout time.Duration) string {
	target := fmt.Sprintf("%s:%s", ip, port)
	remoteAddr, _ := net.ResolveUDPAddr("udp", target)

	conn, err := net.DialUDP("udp", nil, remoteAddr)
	conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		panic(err)
	}

	defer conn.Close()

	msg := []byte(time.Now().String())
	_, err = conn.Write(msg)
	if err != nil {
		panic(err)
	}

	buffer := make([]byte, 1024)
	n, _, _ := conn.ReadFromUDP(buffer)
	if n == 0 {
		return "closed"
	}

	return "open"
}
