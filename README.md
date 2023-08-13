# wgslirpy

A command line tool (and a Rust library) for accepting incoming connections within a Wireguard link and routing them to external network using usual opeating system's socket API.

<img src="wgslirp.svg" alt="Diagram depicting operation of Wgslirpy" width="40%"/>

## Features

* Maintaining Wireguard connection with one peer, using [Boringtun](https://github.com/cloudflare/boringtun) library.
* Decoding incoming TCP or UDP connections using [smoltcp](https://github.com/smoltcp-rs/smoltcp) library
* Forwarding TCP and UDP connections from Wireguard to external world, exchanging traffic userspace and real sockets.
* For UDP, hole punching / NAT traversal should work (not tested though)
* For TCP, half-closed connections and backpressure should work
* Crude DNS server for resolving IPv4 and IPv6 addresses using host DNS implementation

## Limitations

* No ICMP (except of pings to specific address for testing). This affects UDP's "port unreachable"s.
* Forwarding connections _to_ Wireguard network is not yet implemented (but should be reasonable easy to add).


## Demo session

(TODO)

## Installation

Download a pre-built executable from [Github releases](https://github.com/vi/wgslirpy/releases) or install from source code with `cargo install --path .`  or `cargo install wgslirpy`.

## CLI options

<details><summary> wgslirpy --help output</summary>

```
Usage: wgslirpy [-k <private-key>] [-f <private-key-file>] -K <peer-key> [-p <peer-endpoint>] [-a <keepalive-interval>] -b <bind-ip-port> [-D <dns>] [-P <pingable>] [--mtu <mtu>]

Expose internet access without root using Wireguard

Options:
  -k, --private-key main private key of this Wireguard node, base64-encoded
  -f, --private-key-file
                    main private key of this Wireguard node (content of a
                    specified file), base64-encoded
  -K, --peer-key    peer's public key
  -p, --peer-endpoint
                    address of the peer's UDP socket, where to send keepalives
  -a, --keepalive-interval
                    keepalive interval, in seconds
  -b, --bind-ip-port
                    where to bind our own UDP socket for Wireguard connection
  -D, --dns         use this UDP socket address as a simple A/AAAA-only DNS
                    server within Wireguard network
  -P, --pingable    reply to ICMP pings on this single address within Wireguard
                    network
  --mtu             maximum transfer unit to use for TCP. Default is 1420.
  --help            display usage information
```
</details>

## See also

* [onetun](https://github.com/aramperes/onetun) - Similar idea, but is designed to forward connections _to_ Wireguard instead of _from_ Wireguard.
* [SLiRP](https://en.wikipedia.org/wiki/Slirp) - Similar idea, but with PPP (a stream-based connection) instead of packet-based Wireguard.
