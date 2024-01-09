package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	flag.StringVar(&Config.Cert, "cert", "cert.pem", "proxy tls cert")
	flag.StringVar(&Config.Key, "key", "key.pem", "proxy tls key")
	flag.StringVar(&Config.Addr, "addr", "", "proxy listen host")
	flag.StringVar(&Config.Port, "port", "8080", "proxy listen port")
	flag.StringVar(&Config.TLSClient, "client", "Golang", "utls client")
	flag.StringVar(&Config.TLSVersion, "version", "0", "utls client version")
	flag.BoolVar(&Config.Debug, "debug", false, "enable debug")
	flag.Parse()

	if !fileExists(Config.Cert) || !fileExists(Config.Key) {
		if fileExists(Config.Cert) {
			log.Println("found cert, but no corresponding key")
			os.Exit(-1)
		} else if fileExists(Config.Key) {
			log.Println("found key, but no corresponding cert")
			os.Exit(-1)
		}

		log.Println("cert and key do not exist, generating")
		generateCertificate()
	}

	loadCertificate()

	server := &http.Server{
		Addr: Config.Addr + ":" + Config.Port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	fmt.Printf(
		"HTTP Proxy Server listen at %s:%s, with tls fingerprint %s %s\n",
		Config.Addr, Config.Port, Config.TLSVersion, Config.TLSClient,
	)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}
