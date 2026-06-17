package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	cfconfig "github.com/cloudflare/cfssl/config"
	cfsr "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	cfsigner "github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

func (ca *CertificateAuthority) Generate(certPath, keyPath string) error {
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

	ca.tlsCert = tlsCert
	ca.x509Cert = x509Cert

	if err := ensureParentDir(certPath); err != nil {
		return err
	}
	caOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer caOut.Close()
	_, err = caOut.Write(certPEM)
	if err != nil {
		return err
	}

	if err := ensureParentDir(keyPath); err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0700)
}

func (session *SessionKeyHelper) Generate() error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	derBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}

	PEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})

	session.privateKey = privKey
	session.PEMBlock = PEMBlock

	return nil
}

// Credit: elazarl/goproxy (https://github.com/elazarl/goproxy/blob/7cc037d33fb57d20c2fa7075adaf0e2d2862da78/https.go#L50)
func stripPort(s string) string {
	host, _, err := net.SplitHostPort(s)
	if err == nil {
		return host
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	}
	return s
}

func (ca *CertificateAuthority) GenerateCertificate(session SessionKeyHelper, sni string) (tls.Certificate, error) {
	if session.privateKey == nil || len(session.PEMBlock) == 0 {
		return tls.Certificate{}, fmt.Errorf("session key has not been generated")
	}
	if ca.x509Cert == nil {
		return tls.Certificate{}, fmt.Errorf("CA certificate has not been loaded")
	}
	cryptoSigner, ok := ca.tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("CA private key is not a crypto signer")
	}

	hostname := stripPort(sni)
	request := &cfsr.CertificateRequest{
		CN:         hostname,
		Hosts:      []string{hostname},
		KeyRequest: cfsr.NewKeyRequest(),
	}

	csrBytes, err := cfsr.Generate(session.privateKey, request)
	if err != nil {
		return tls.Certificate{}, err
	}

	profile := cfconfig.DefaultConfig()
	policy := &cfconfig.Signing{
		Default: profile,
	}

	signer, err := local.NewSigner(cryptoSigner, ca.x509Cert, cfsigner.DefaultSigAlgo(cryptoSigner), policy)
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

	tlsCert, err := tls.X509KeyPair(certBytes, session.PEMBlock)
	return tlsCert, err
}

func (ca *CertificateAuthority) Load(certPath, keyPath string) error {
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	} else {
		x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return err
		}

		ca.tlsCert = tlsCert
		ca.x509Cert = x509Cert

		return nil
	}
}
