# scanport

![GitHub License](https://img.shields.io/github/license/dapacruz/scanport)
![Go Version](https://img.shields.io/badge/go-1.13%2B-blue)

A fast, multi-threaded TCP/UDP port scanner written in Go.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Sample Output](#sample-output)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- Scan TCP and UDP ports simultaneously
- Scan multiple hosts in a single command
- Accepts both hostnames and IP addresses (with automatic reverse DNS lookup)
- Configurable connection timeout and worker thread count
- Color-coded output: open ports in green, closed ports in red
- Concurrent scanning via goroutines for maximum speed

## Requirements

- [Go 1.13+](https://go.dev/dl/)

## Installation

Install directly with `go install`:

```bash
go install github.com/Dapacruz/scanport@latest
```

The binary will be placed in your `$GOPATH/bin` (or `$HOME/go/bin` by default). Make sure that directory is in your `$PATH`.

Alternatively, build from source:

```bash
git clone https://github.com/Dapacruz/scanport.git
cd scanport
go build -o scanport .
```

## Usage

```
scanport -host <host[,host...]> [-tcp <port[,port...]>] [-udp <port[,port...]>] [options]
```

At least one `-host` and one port flag (`-tcp` or `-udp`) are required.

## Options

| Flag    | Default | Description                                         |
|---------|---------|-----------------------------------------------------|
| `-host` | —       | Comma-separated list of hostnames and/or IP addresses to scan |
| `-tcp`  | —       | Comma-separated list of TCP ports to scan           |
| `-udp`  | —       | Comma-separated list of UDP ports to scan           |
| `-t`    | `1`     | Connection timeout in seconds                       |
| `-w`    | `100`   | Maximum number of concurrent worker threads         |

## Examples

Scan a single host for common web ports over TCP:

```bash
scanport -host www.example.com -tcp 80,443
```

Scan multiple IP addresses for a UDP port:

```bash
scanport -host 8.8.8.8,8.8.4.4 -udp 53
```

Scan multiple hosts for both TCP and UDP ports with a custom timeout:

```bash
scanport -host www.google.com,www.vmware.com -tcp 80,443 -udp 53 -t 5
```

Reduce concurrency to avoid connection limits:

```bash
scanport -host 192.168.1.1 -tcp 22,80,443,8080 -w 10
```

## Sample Output

```
Scanning ports ...

93.184.216.34 (www.example.com) ==> TCP/80 is open
93.184.216.34 (www.example.com) ==> TCP/443 is open

Scan complete: 1 host(s) scanned in 0.243 seconds
```

Open ports are printed in **green** and closed ports in **red**.

## Troubleshooting

**`too many open files` error**
This occurs when the number of concurrent connections exceeds your OS's open file descriptor limit. Lower the worker count with `-w`:

```bash
scanport -host <target> -tcp <ports> -w 20
```

You can also raise the system limit temporarily:

```bash
ulimit -n 4096
```

**Host cannot be resolved**
Ensure the hostname is spelled correctly and that your DNS is reachable. You can also pass an IP address directly with `-host`.

**UDP scan results are unreliable**
UDP is a connectionless protocol. A port reported as "closed" means no response was received within the timeout window — this can be a false negative due to firewalls or packet loss. Increase the timeout with `-t` for more reliable results:

```bash
scanport -host <target> -udp 53 -t 5
```

## License

This project is licensed under the [MIT License](LICENSE).
