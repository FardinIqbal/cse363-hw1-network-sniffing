# Argus

> Passive network sniffer that identifies HTTP, TLS, and DNS by payload, not port.

Argus captures packets from a live interface or a pcap file and classifies each
one by inspecting its payload bytes — so HTTP on port 8080, DNS on port 5353,
and TLS on port 993 are all detected like their standard-port counterparts.
It extracts TLS SNI with a dual-strategy parser (Scapy layer first, manual
binary walker as fallback), flags HTTP traffic from automation tools, and
tags DNS queries for `.local`, `.corp`, and `.internal` TLDs. Validated with
12 crafted test cases covering every protocol × standard/non-standard port ×
variant combination.

## What it is

A single-file Python sniffer (`argus.py`) built on Scapy. It reads raw TCP and
UDP payloads and classifies each packet against three protocol signatures
instead of trusting the port number. Output is one line per classified packet
with timestamp, 5-tuple, protocol tag, and parsed detail.

## Key features

- **Port-independent protocol detection.** HTTP is matched by `GET `, `POST `,
  `PUT ` prefixes on the TCP payload. TLS is matched by the record signature
  `0x16 0x03 ... 0x01`. DNS is matched by parsing the raw UDP payload as DNS
  wire format (RFC 1035).
- **Dual-strategy TLS SNI extraction.** Tries Scapy's `TLSClientHello`
  extension list first; if Scapy can't parse the record, a manual binary
  parser walks the ClientHello byte-by-byte using `struct.unpack` — skipping
  record header, handshake header, version, random, session ID, cipher
  suites, and compression methods — then scans extensions for type `0x0000`
  (server_name) and decodes the hostname.
- **Automation tool detection.** HTTP requests whose User-Agent matches one of
  8 patterns (`curl/`, `wget/`, `python-requests`, `python-urllib`,
  `python-httpx`, `libwww-perl`, `go-http-client`, `httpie`) are tagged
  `AUTOMATION` with the full UA string.
- **Internal infrastructure flagging.** DNS A queries for domains ending in
  `.local`, `.corp`, or `.internal` are tagged `INTERNAL`. These are
  non-routable TLDs; their appearance in external-facing captures usually
  indicates DNS leakage or misconfigured resolvers.
- **BPF filter support.** tcpdump-style filter expressions are pushed down to
  the capture layer for kernel-side filtering.
- **Live and offline capture.** Read from `-i <iface>` or `-r <pcap>`.

## Quick start

Install:

```bash
pip install -r requirements.txt
```

Read the included test pcap:

```bash
python3 argus.py -r test.pcap
```

Live capture (requires root for raw sockets):

```bash
sudo python3 argus.py -i eth0
```

With a BPF filter:

```bash
sudo python3 argus.py -i eth0 "host 10.0.0.1 and port 443"
```

## Architecture

```
           +------------------+
           |  Packet Capture  |   scapy.sniff()  (-i iface | -r pcap)
           +--------+---------+
                    |
                    v
            +---------------+
            |   IP filter   |
            +-------+-------+
                    |
         +----------+----------+
         |                     |
      haslayer(UDP)        haslayer(TCP)
         |                     |
         v                     v
   +-----------+       +----------------+       +---------------+
   |    DNS    |       |      HTTP      |  -->  |      TLS      |
   |  handler  |       |    handler     |       |    handler    |
   +-----+-----+       +--------+-------+       +-------+-------+
         |                      |                       |
         v                      v                       v
   qname (+ INTERNAL)    host + method + path     SNI  (Scapy ext
                         (+ AUTOMATION ua)         list  OR  manual
                                                   byte-walker)
                    |
                    v
           +------------------+
           |   _emit() line   |   ts  PROTO  src:sport -> dst:dport  detail
           +------------------+
```

Dispatch is table-driven: `HANDLERS = [(UDP, handle_dns, "DNS"), (TCP,
handle_http, "HTTP"), (TCP, handle_tls, "TLS")]`. Each handler returns a
detail string on match or `None` to fall through.

## Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| Capture / parsing | Scapy (`>=2.5.0`) |
| TLS layer support | `cryptography` (`>=41.0.0`), optional at runtime |
| Binary parsing | stdlib `struct` for manual TLS extension walking |
| Packaging | `pyproject.toml` + setuptools, `argus` console entry point |

## Testing

Regenerate the synthetic pcap (12 packets, 4 per protocol):

```bash
python3 generate_test_pcap.py
```

Run Argus against it:

```bash
python3 argus.py -r test.pcap
```

Full integration test on a Linux VM — starts local HTTP servers on 8080/9090,
runs `tcpdump` on both `eth0` and `lo`, issues real `dig`, `curl`, and
`openssl s_client` traffic for all 12 cases, merges captures with `mergecap`,
then parses with Argus and verifies coverage:

```bash
sudo bash capture.sh
```

Coverage matrix (from `test.out`, 16 classified lines):

| # | Protocol | Port | Variant | Tag |
|---|----------|------|---------|-----|
| 1 | DNS | 53 | Standard A query | — |
| 2 | DNS | 5353 | Non-standard port | — |
| 3 | DNS | 53 | `.local` TLD | `INTERNAL` |
| 4 | DNS | 1053 | Non-standard + `.corp` TLD | `INTERNAL` |
| 5 | HTTP | 80 | Standard GET | — |
| 6 | HTTP | 8080 | Non-standard GET | — |
| 7 | HTTP | 80 | POST | `AUTOMATION curl/8.11.1` |
| 8 | HTTP | 9090 | Non-standard PUT | `AUTOMATION python-requests/2.31.0` |
| 9 | TLS | 443 | Standard + SNI | `google.com` |
| 10 | TLS | 993 | Non-standard + SNI | `imap.gmail.com` |
| 11 | TLS | 443 | Standard, no SNI | `NO SNI` |
| 12 | TLS | 993 | Non-standard, no SNI | `NO SNI` |

## Example output

```
2026-02-27 17:18:54.018302 DNS  192.168.64.6:46465 -> 8.8.8.8:53 www.example.org
2026-02-27 17:18:55.093730 DNS  192.168.64.6:49435 -> 8.8.8.8:53 esxi1.local INTERNAL
2026-02-27 17:18:55.128255 DNS  192.168.64.6:34553 -> 8.8.8.8:1053 db.corp INTERNAL
2026-02-27 17:18:56.292564 HTTP 192.168.64.6:40378 -> 23.185.0.4:80 www.example.org GET /test/
2026-02-27 17:18:56.339704 HTTP 127.0.0.1:55814 -> 127.0.0.1:8080 127.0.0.1:8080 GET /
2026-02-27 17:18:56.369320 HTTP 192.168.64.6:40392 -> 23.185.0.4:80 www.example.org POST /test/ AUTOMATION curl/8.11.1
2026-02-27 17:18:56.489375 HTTP 127.0.0.1:36150 -> 127.0.0.1:9090 127.0.0.1:9090 PUT /upload AUTOMATION python-requests/2.31.0
2026-02-27 17:18:56.587896 TLS  192.168.64.6:57114 -> 142.251.45.78:443 google.com
2026-02-27 17:18:56.642299 TLS  192.168.64.6:46096 -> 172.253.62.109:993 imap.gmail.com
2026-02-27 17:18:56.701582 TLS  192.168.64.6:57118 -> 142.251.45.78:443 NO SNI
```

## How it works

### DNS

DNS has a fixed wire format: 12-byte header + question section. The handler
first checks for an already-parsed Scapy `DNS`/`DNSQR` layer; if absent, it
takes the raw UDP payload and constructs `DNS(raw)` directly. That makes
detection port-agnostic. Only queries (`qr == 0`) of type A (`qtype == 1`)
are emitted. Names ending in `.local`, `.corp`, or `.internal` get the
`INTERNAL` tag.

### HTTP

Three-tier fallback: (1) Scapy-parsed `HTTPRequest` layer → pull `Method`,
`Host`, `Path`, `User_Agent`; (2) raw TCP payload starting with `GET `,
`POST `, or `PUT ` → construct `HTTPRequest` from bytes; (3) if Scapy's
constructor fails, a manual ASCII parser splits on `\r\n` and builds a header
dict. Only `GET`/`POST`/`PUT` methods are reported. User-Agent is matched
case-insensitively against the automation pattern tuple.

### TLS

A five-byte precheck on the raw payload — `raw[0] == 0x16`,
`raw[1] == 0x03`, `raw[5] == 0x01` — gates all further work, so non-TLS
traffic is rejected before any parsing attempt. If Scapy's TLS module is
present and parsed a `TLSClientHello`, SNI comes from `TLS_Ext_ServerName`.
Otherwise the manual parser walks the ClientHello:

1. Skip 5 (record) + 4 (handshake) = 9 bytes, then 2 (version) + 32 (random)
   to offset 43.
2. Read 1-byte session-ID length, skip.
3. Read 2-byte cipher-suites length, skip.
4. Read 1-byte compression-methods length, skip.
5. Read 2-byte extensions length → compute `ext_end`.
6. Walk extensions: `(type uint16, length uint16, data)`. On `type == 0x0000`
   (server_name), confirm host_name indicator (`data[pos+2] == 0x00`), read
   the 2-byte name length, decode the bytes.

If no server_name extension is present (e.g. `openssl s_client -noservername`),
output is `NO SNI`.

## Project context

Argus is part of a five-project security-research portfolio. Development ran
from the initial commit on 2026-02-27 through the April 2026 cleanup pass
that landed the capture script, pyproject packaging, and the final README
audit (commit `4e1c676`). Related repos are linked from the portfolio site.

Notable commits:

- `e04ef85` Add Argus network sniffer with port-independent protocol detection
- `2af5ce7` Add test pcap with 12 cases and expected output
- `a2dcb43` Refactor for elegance: table-driven dispatch, DRY protocol handlers
- `0baea1f` Restrict DNS to A records only
- `d849893` Add capture script for Kali VM
- `0c70bb5` Fix TLS capture: force IPv4 + TCP payload fallback
- `482a4d2` Rebrand as Argus: professional README, clean project structure

## Requirements

- Python 3.11+
- `scapy >= 2.5.0`
- `cryptography >= 41.0.0` (optional at runtime; enables Scapy's TLS layer
  and improves parse rates — the manual binary parser covers the gap when
  it's absent)
- Root / sudo for live capture (reading pcap files does not)

## License

MIT. See [LICENSE](LICENSE).
