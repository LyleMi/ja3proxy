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
        upstream proxy, e.g. 127.0.0.1:1080, socks5 only
  -debug
        enable debug
```

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
