package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"

	cfconfig "github.com/cloudflare/cfssl/config"
	cfsr "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	cfsigner "github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

func generateCA() error {
	csr := cfsr.CertificateRequest{
		CN:         "ja3proxy CA",
		KeyRequest: cfsr.NewKeyRequest(),
	}

	certPEM, _, keyPEM, err := initca.New(&csr)
	if err != nil {
		return err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

	CA.tlsCert = tlsCert
	CA.x509Cert = x509Cert

	caOut, err := os.Create(Config.Cert)
	if err != nil {
		return err
	}
	defer caOut.Close()
	_, err = caOut.Write(certPEM)
	if err != nil {
		return err
	}

	keyOut, err := os.OpenFile(Config.Key, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	_, err = keyOut.Write(keyPEM)
	if err != nil {
		return err
	}

	return nil
}

func generateSessionKey() error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	derBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}

	PEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})

	SessionKey.privateKey = privKey
	SessionKey.PEMBlock = PEMBlock

	return nil
}

// Credit: elazarl/goproxy (https://github.com/elazarl/goproxy/blob/7cc037d33fb57d20c2fa7075adaf0e2d2862da78/https.go#L50)
func stripPort(s string) string {
	var ix int
	if strings.Contains(s, "[") && strings.Contains(s, "]") {
		//ipv6 : for example : [2606:4700:4700::1111]:443

		//strip '[' and ']'
		s = strings.ReplaceAll(s, "[", "")
		s = strings.ReplaceAll(s, "]", "")

		ix = strings.LastIndexAny(s, ":")
		if ix == -1 {
			return s
		}
	} else {
		//ipv4
		ix = strings.IndexRune(s, ':')
		if ix == -1 {
			return s
		}

	}
	return s[:ix]
}

func generateCertificate(sni string) (tls.Certificate, error) {
	hostname := stripPort(sni)
	request := &cfsr.CertificateRequest{
		CN:         hostname,
		Hosts:      []string{hostname},
		KeyRequest: cfsr.NewKeyRequest(),
	}

	csrBytes, err := cfsr.Generate(SessionKey.privateKey, request)
	if err != nil {
		return tls.Certificate{}, err
	}

	cryptoSigner := CA.tlsCert.PrivateKey.(crypto.Signer)
	profile := cfconfig.DefaultConfig()
	policy := &cfconfig.Signing{
		Default: profile,
	}

	signer, err := local.NewSigner(cryptoSigner, CA.x509Cert, cfsigner.DefaultSigAlgo(cryptoSigner), policy)
	if err != nil {
		return tls.Certificate{}, err
	}

	signRequest := cfsigner.SignRequest{
		Request: string(csrBytes),
		Subject: &cfsigner.Subject{
			CN: request.CN,
		},
		Hosts: request.Hosts,
	}

	certBytes, err := signer.Sign(signRequest)
	if err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certBytes, SessionKey.PEMBlock)
	return tlsCert, err
}

func loadExistingCA() error {
	tlsCert, err := tls.LoadX509KeyPair(Config.Cert, Config.Key)
	if err != nil {
		return err
	} else {
		x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return err
		}

		CA.tlsCert = tlsCert
		CA.x509Cert = x509Cert

		return nil
	}
}
