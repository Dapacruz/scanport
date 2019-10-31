package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var wg sync.WaitGroup

// Create objects to colorize stdout
var (
	green = color.New(color.FgGreen)
	red   = color.New(color.FgRed)
	blue  = color.New(color.FgBlue)
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

	queue := make(chan [][]string, 100)

	flag.Var(&hosts, "host", "Comma-separated list of hostnames and/or IP addresses of host to scan")
	flag.Var(&tcpPorts, "tcp", "Comma-separated list of TCP ports to scan")
	flag.Var(&udpPorts, "udp", "Comma-separated list of UDP ports to scan")
	t := flag.String("t", "1", "Connection timeout in seconds")

	flag.Parse()

	// Ensure at least one host and port are defined, otherwise exit and display usage
	if len(hosts) == 0 || (len(tcpPorts) == 0 && len(udpPorts) == 0) {
		flag.Usage()
		os.Exit(1)
	}

	timeout, _ := time.ParseDuration(*t + "s")

	fmt.Printf("\nScanning ports ...\n\n")

	for _, host := range hosts {
		wg.Add(1)
		go scanHost(host, timeout, queue, tcpPorts, udpPorts)
	}

	wg.Wait()

	close(queue)
	for i := range queue {
		for _, r := range i {
			printResults(r[0], r[1], r[2], r[3], r[4])
		}

		fmt.Println()
	}
}

func scanHost(host string, timeout time.Duration, queue chan [][]string, tcpPorts, udpPorts arrayFlagString) {
	var results [][]string
	addr, hostname := resolveHost(host)

	defer wg.Done()

	for _, p := range tcpPorts {
		state := scanTCPPort(addr, p, timeout)
		results = append(results, []string{addr, hostname, p, "TCP", state})
	}

	for _, p := range udpPorts {
		state := scanUDPPort(addr, p, timeout)
		results = append(results, []string{addr, hostname, p, "UDP", state})
	}

	queue <- results
}

func printResults(addr, hostname, port, protocol, state string) {
	if state == "open" {
		fmt.Printf("%v (%v) ==> %v/%v is ", addr, hostname, protocol, port)
		green.Println(state)
	} else {
		fmt.Printf("%v (%v) ==> %v/%v is ", addr, hostname, protocol, port)
		red.Println(state)
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
