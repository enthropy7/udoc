![docs.rs](https://img.shields.io/docsrs/udoc) ![Crates.io Version](https://img.shields.io/crates/v/udoc)

# udoc

> Ultimate connection diagnostics for URLs: DNS/TCP/TLS/TTFB timings + h2 support + cert summary + redirects + bottleneck analysis.
> urldoc (`udoc`) is a minimal CLI that prints a concise connection report for any HTTP/HTTPS URL.
Run `udoc <url>` to see the final URL after redirects, the actual IP:port you hit, and the negotiated protocol details.
It breaks latency down into phases (DNS, TCP connect, TLS handshake, TTFB, total) so you can instantly spot where time is spent.
For HTTPS, it summarizes TLS parameters (version, ALPN, cipher) and the leaf certificate (issuer/subject, validity window, days left, SHA-256 fingerprint).
The output is designed to be readable by humans first—no verbosity, no “curl -v” noise—just the signal you need for debugging.
Internally, the project follows Clean Architecture with strict separation between domain models, use cases, and infrastructure adapters. Easy to modify, if you want.

## Install

```bash
cargo install udoc
```

## Usage

```bash
udoc [--json] <URL>
```

## Example

```
$ udoc http://github.com

200 OK  h2  ip=140.82.121.3  total=1791ms  ttfb=99ms  tls=TLS1.3  bottleneck=tls

URL
  input:  http://github.com
  final:  https://github.com/
  host:   github.com
  ip:     140.82.121.3:443   (ipv4)

REDIRECTS (1)
  [301] http://github.com/ → https://github.com/
      dns=73.6ms tcp=3.8ms ttfb=264.3ms

HTTP
  status: 200 OK
  proto:  HTTPS
  ver:    h2

TIMINGS
  dns:        73.6 ms
  tcp:         9.7 ms
  tls:       271.1 ms
  ttfb:       99.1 ms
  total:    1791.1 ms

TLS
  version: TLS1.3
  alpn:    h2
  cipher:  TLS13_AES_128_GCM_SHA256
  chain:   3 certs
  verify:  ok

CERT
  subject: CN=github.com
  issuer:  Sectigo ECC Domain Validation Secure Server CA
  san:     github.com (+1)
  valid:   2025-02-05 → 2026-02-05  (days_left: 39)
  sha256:  b8:bb:...:f5
```

## Features

- **HTTP/2**: Real h2 support via ALPN negotiation (hyper)
- **HTTP/1.1**: Raw client for http/1.1 connections
- **Redirects**: Follows 301/302/303/307/308 up to 10 hops with per-hop timings
- **Bottleneck analysis**: Identifies slowest phase (dns/tcp/tls/ttfb)
- **Timings**: DNS, TCP connect, TLS handshake, TTFB, total
- **TLS**: Version, ALPN, cipher, chain length, verification status
- **Certificate**: Subject, issuer, SAN, validity, SHA-256 fingerprint
- **Warnings**: HTTPS→HTTP downgrade, cert expiring (<14 days)
- **JSON output**: `--json` for scripting/pipelines
- **Summary line**: Quick overview at the top

## Options

```
--json, -j    Output as JSON
--help, -h    Show usage
```

## Environment

```
UDOC_TIMEOUT      Request timeout (e.g. 5s, 3000ms) [default: 5s]
UDOC_MAX_REDIRS   Max redirects [default: 10]
UDOC_BODY_LIMIT   Body preview limit in bytes [default: 32768]
UDOC_REPEAT       Repeat count for stats [default: 1]
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Invalid input |
| 3 | DNS failed |
| 4 | TCP failed |
| 5 | TLS failed |
| 6 | HTTP error |
| 7 | Timeout |
| 1 | Other |

## License

MIT
