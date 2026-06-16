# JA3Proxy

JA3Proxy is an HTTP proxy that uses
[uTLS](https://github.com/refraction-networking/utls) to create outbound TLS
connections with configurable ClientHello fingerprints. It can be used to test
how applications behave behind different browser-like TLS fingerprints, while
keeping a familiar HTTP proxy interface for clients.

## Features

- HTTP and HTTPS proxy support.
- Customizable TLS ClientHello fingerprints through uTLS presets.
- Dynamic MITM certificates for HTTPS `CONNECT` traffic.
- Automatic local CA generation when no certificate/key pair is provided.
- Optional SOCKS5 upstream proxy for both HTTP and HTTPS traffic.
- Docker and Docker Compose examples included.

## How it works

For plain HTTP requests, JA3Proxy forwards the request directly. For HTTPS
`CONNECT` requests, it establishes a TLS connection to the upstream server using
the configured uTLS fingerprint, then serves a dynamically generated certificate
to the client using the local CA.

Because HTTPS traffic is intercepted, clients must either trust the generated CA
certificate or explicitly skip certificate verification for testing.

## Quick start

### Build from source

Requirements:

- Go 1.24 or newer
- `make` if you want to use the provided Makefile

```bash
git clone https://github.com/lylemi/ja3proxy.git
cd ja3proxy

go build -o ja3proxy .
./ja3proxy -port 8080 -client 360Browser -version 7.5
```

Test the proxy:

```bash
curl -v -k --proxy http://127.0.0.1:8080 https://www.example.com
```

The first run creates `credentials/cert.pem` and `credentials/key.pem` if they
do not already exist.

### Docker

```bash
mkdir -p credentials

docker run --rm \
  -v ./credentials:/app/credentials \
  -p 8080:8080 \
  ghcr.io/lylemi/ja3proxy:latest \
  -cert /app/credentials/cert.pem \
  -key /app/credentials/key.pem \
  -client 360Browser \
  -version 7.5
```

### Docker Compose

```bash
docker compose up -d
```

See [compose.yaml](./compose.yaml) for the full service definition.

## Configuration

```text
Usage of ja3proxy:
  -addr string
        proxy listen host
  -port string
        proxy listen port (default "8080")
  -cert string
        proxy CA cert (default "credentials/cert.pem")
  -key string
        proxy CA key (default "credentials/key.pem")
  -client string
        utls client (default "Golang")
  -version string
        utls client version (default "0")
  -upstream string
        upstream proxy, e.g. 127.0.0.1:1080, socks5 only
  -debug
        enable debug
```

Example with a SOCKS5 upstream proxy:

```bash
./ja3proxy \
  -port 8080 \
  -client Chrome \
  -version 106 \
  -upstream socks5://127.0.0.1:1080
```

The `-upstream` flag also accepts `host:port`, for example
`127.0.0.1:1080`. Only SOCKS5 upstream proxies are supported.

## TLS fingerprints

JA3Proxy passes the `-client` and `-version` values to uTLS. Supported presets
depend on the uTLS version used by this project. See the uTLS
[ClientHelloID definitions](https://github.com/refraction-networking/utls/blob/master/u_common.go)
for the authoritative list.

Common presets:

| Client | Version |
| --- | --- |
| Golang | 0 |
| Firefox | 55, 56, 63, 99, 105 |
| Chrome | 58, 62, 70, 96, 102, 106 |
| iOS | 12.1, 13, 14 |
| Android | 11 |
| Edge | 85, 106 |
| Safari | 16.0 |
| 360Browser | 7.5 |
| QQBrowser | 11.1 |

## Certificates

JA3Proxy needs a CA certificate and private key to generate per-host
certificates for HTTPS interception.

- If both files exist, they are loaded from `-cert` and `-key`.
- If neither file exists, JA3Proxy generates a new CA pair.
- If only one file exists, startup fails to avoid using a mismatched pair.

By default, generated CA files are written to `credentials/cert.pem` and
`credentials/key.pem`. If the configured paths include missing directories,
JA3Proxy creates them before writing the files.

For browser or application testing, import the generated CA certificate into the
client trust store. For one-off command-line checks, tools such as `curl -k`
can skip verification.

## Development

Run the test suite:

```bash
go test ./...
```

Build release binaries with the Makefile:

```bash
make
```

This creates Linux and Windows AMD64 binaries in the `bin/` directory.

## Security notice

JA3Proxy performs TLS interception and can expose decrypted traffic to the
machine running the proxy. Use it only in environments where you have permission
to inspect the traffic. Protect generated CA private keys carefully and remove
them from client trust stores when they are no longer needed.

## Contributing

Issues and pull requests are welcome. Please include a clear description,
reproduction steps when reporting bugs, and tests for behavior changes when
practical.

## License

This project is licensed under the [MIT License](./LICENSE).
