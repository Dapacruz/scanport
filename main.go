// Package scanport is a very fast multi-threaded TCP/UDP port scanner
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
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

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "EXAMPLES:\n")
		fmt.Fprintf(os.Stderr, "  scanport -host www.boeing.com -tcp 80,443\n")
		fmt.Fprintf(os.Stderr, "  scanport -host 8.8.8.8,8.8.4.4 -udp 53\n")
		fmt.Fprintf(os.Stderr, "  scanport -host www.google.com,www.vmware.com -tcp 80,443 -udp 53 -t 5\n\n")
		fmt.Fprintf(os.Stderr, "OPTIONS:\n")
		flag.PrintDefaults()
	}

	flag.Var(&hosts, "host", "Comma-separated list of hostnames and/or IP addresses of host to scan")
	flag.Var(&tcpPorts, "tcp", "Comma-separated list of TCP ports to scan")
	flag.Var(&udpPorts, "udp", "Comma-separated list of UDP ports to scan")
	t := flag.Int("t", 1, "Connection timeout in seconds")
	maxWorkers := flag.Int("w", 100, "Max concurrent worker threads")

	flag.Parse()

	// Ensure at least one host and port are defined, otherwise exit and display usage
	if len(hosts) == 0 || (len(tcpPorts) == 0 && len(udpPorts) == 0) {
		flag.Usage()
		os.Exit(1)
	}

	timeout, _ := time.ParseDuration(strconv.Itoa(*t) + "s")

	queue := make(chan []map[string]string, 100)
	workers := make(chan int, *maxWorkers)
	done := make(chan bool)

	fmt.Printf("\nScanning ports ...\n\n")

	go printResults(queue, done)

	start := time.Now()
	for _, host := range hosts {
		wg.Add(1)
		workers <- 1
		go scanHost(host, timeout, queue, workers, tcpPorts, udpPorts)
	}
	wg.Wait()
	elapsed := time.Since(start)

	close(queue)
	<-done

	fmt.Printf("Scan complete: %d host(s) scanned in %.3f seconds\n", len(hosts), elapsed.Seconds())
}

func scanHost(host string, timeout time.Duration, queue chan []map[string]string, workers chan int, tcpPorts, udpPorts arrayFlagString) {
	var results []map[string]string
	addr, hostname := resolveHost(host)

	defer wg.Done()

	for _, p := range tcpPorts {
		state := scanTCPPort(addr, p, timeout)
		results = append(results, map[string]string{
			"addr":     addr,
			"hostname": hostname,
			"port":     p,
			"protocol": "TCP",
			"state":    state,
		})
	}

	for _, p := range udpPorts {
		state := scanUDPPort(addr, p, timeout)
		results = append(results, map[string]string{
			"addr":     addr,
			"hostname": hostname,
			"port":     p,
			"protocol": "UDP",
			"state":    state,
		})
	}

	queue <- results
	<-workers
}

func printResults(queue <-chan []map[string]string, done chan<- bool) {
	for {
		if results, queueIsOpen := <-queue; queueIsOpen {
			for _, r := range results {
				fmt.Printf("%v (%v) ==> %v/%v is ", r["addr"], r["hostname"], r["protocol"], r["port"])
				if r["state"] == "open" {
					green.Println(r["state"])
				} else {
					red.Println(r["state"])
				}
			}
			fmt.Println()
		} else {
			done <- true
			return
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
