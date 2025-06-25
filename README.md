# JA3Proxy

Customizing TLS (JA3) Fingerprints through HTTP Proxy

## Usage

### Building from source

```bash
git clone https://github.com/lylemi/ja3proxy
cd ja3proxy
make
./ja3proxy -port 8080 -client 360Browser -version 7.5

curl -v -k --proxy http://localhost:8080 https://www.example.com
```

### Using docker CLI

```bash
docker run \
      -v ./credentials:/app/credentials \
      -p 8080:8080 \
      ghcr.io/lylemi/ja3proxy:latest \
      -cert /app/credentials/cert.pem \
      -key /app/credentials/key.pem \
      -client 360Browser \
      -version 7.5
```

### Using docker compose

See [`compose.yaml`](https://github.com/LyleMi/ja3proxy/blob/master/compose.yaml)

```bash
docker compose up -d
```

### CLI usage

```bash
Usage of ja3proxy:
  -addr string
        proxy listen host
  -port string
        proxy listen port (default "8080")
  -cert string
        proxy tls cert (default "cert.pem")
  -key string
        proxy tls key (default "key.pem")
  -client string
        utls client (default "Golang")
  -version string
        utls client version (default "0")
  -upstream string
        upstream proxy, e.g. http://user:pass@host:port or socks5://user:pass@host:port
  -debug
        enable debug
```

### Dynamic Proxy Configuration via Headers

You can configure proxy settings per request using HTTP headers:

```bash
# Set timeout to 15 seconds
curl -H "tls-timeout: 15" --proxy http://localhost:8080 https://www.example.com

# Use specific proxy for this request
curl -H "tls-proxy: http://127.0.0.1:1080" --proxy http://localhost:8080 https://www.example.com

# Force HTTPS upgrade (HTTP requests will be upgraded to HTTPS)
curl -H "tls-https: true" --proxy http://localhost:8080 http://www.example.com

# Combine multiple settings
curl -H "tls-timeout: 20" -H "tls-proxy: socks5://127.0.0.1:1080" -H "tls-https: true" --proxy http://localhost:8080 http://www.example.com
```

**Header Parameters:**
- `tls-timeout`: Timeout in seconds for proxy requests (default: 10)
- `tls-proxy`: Proxy URL for this request (supports http:// and socks5://)
- `tls-https`: Force HTTPS upgrade for HTTP requests (set to "true")

**Note:** These headers are automatically removed before forwarding requests to target servers.

### Perdefined clients and versions

> for full list, see: https://github.com/refraction-networking/utls/blob/master/u_common.go

| Client | Version |
| ------ | ------- |
| Golang | 0 |
| Firefox | 55 |
| Firefox | 56 |
| Firefox | 63 |
| Firefox | 99 |
| Firefox | 105 |
| Chrome | 58 |
| Chrome | 62 |
| Chrome | 70 |
| Chrome | 96 |
| Chrome | 102 |
| Chrome | 106 |
| iOS | 12.1 |
| iOS | 13 |
| iOS | 14 |
| Android | 11 |
| Edge | 85 |
| Edge | 106 |
| Safari | 16.0 |
| 360Browser | 7.5 |
| QQBrowser | 11.1 |

## Contribution

If you have any ideas or suggestions, please feel free to submit a pull request. We appreciate any contributions.

## Contact

If you have any questions or suggestions, please feel free to contact us.
