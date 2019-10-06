// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package webpagereplay

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"

	//"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Returns a TLS configuration that serves a recorded server leaf cert signed by
// root CA.
func ReplayTLSConfig(root tls.Certificate, a *Archive) (*tls.Config, error) {
	root_cert, err := getRootCert(root)
	if err != nil {
		return nil, fmt.Errorf("bad local cert: %v", err)
	}
	tp := &tlsProxy{&root, root_cert, a, nil, sync.Mutex{}, make(map[string][]byte)}
	return &tls.Config{
		GetConfigForClient: tp.getReplayConfigForClient,
	}, nil
}

// Returns a TLS configuration that serves a server leaf cert fetched over the
// network on demand.
func RecordTLSConfig(root tls.Certificate, w *WritableArchive) (*tls.Config, error) {
	root_cert, err := getRootCert(root)
	if err != nil {
		return nil, fmt.Errorf("bad local cert: %v", err)
	}
	tp := &tlsProxy{&root, root_cert, nil, w, sync.Mutex{}, nil}
	return &tls.Config{
		GetConfigForClient: tp.getRecordConfigForClient,
	}, nil
}

func getRootCert(root tls.Certificate) (*x509.Certificate, error) {
	root_cert, err := x509.ParseCertificate(root.Certificate[0])
	if err != nil {
		return nil, err
	}
	root_cert.IsCA = true
	root_cert.BasicConstraintsValid = true
	return root_cert, nil
}

// Mints a dummy server cert when the real one is not recorded.
func MintDummyCertificate(serverName string, rootCert *x509.Certificate, rootKey crypto.PrivateKey) ([]byte, string, string, error) {
	template := rootCert
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}
	var buf [20]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, "", "", fmt.Errorf("create cert failed: %v", err)
	}
	template.SerialNumber.SetBytes(buf[:])
	template.Issuer = template.Subject
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, rootKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("create cert failed: %v", err)
	}
	//return derBytes, "", net.ParseIP(serverName).String(), err
	return derBytes, "", "", err
}

// Returns DER encoded server cert.
func MintServerCert(serverName string, rootCert *x509.Certificate, rootKey crypto.PrivateKey) ([]byte, string, string, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", serverName), &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("Couldn't reach host %s: %v", serverName, err)
	}
	defer conn.Close()
	conn.Handshake()
	ip := conn.RemoteAddr()
	log.Print(fmt.Sprintf("%s ", serverName) + fmt.Sprintf("%s ", ip))
	template := conn.ConnectionState().PeerCertificates[0]
	/*subject := "dummy"
	if serverName == "www.msn.com" {
		subject = "www.msn.com"
	} else {
		subject = conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	template := x509.Certificate{

		SerialNumber: conn.ConnectionState().PeerCertificates[0].SerialNumber,

		Subject: pkix.Name{

			CommonName: subject,
		},

		Issuer: rootCert.Subject,

		NotBefore: time.Now(),

		NotAfter: time.Now().Add(time.Hour * 24 * 180),

		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		IsCA: true,

		AuthorityKeyId: conn.ConnectionState().PeerCertificates[0].AuthorityKeyId,

		CRLDistributionPoints: conn.ConnectionState().PeerCertificates[0].CRLDistributionPoints,

		IssuingCertificateURL: conn.ConnectionState().PeerCertificates[0].IssuingCertificateURL,

		DNSNames: []string{serverName},

		PublicKey: rootCert.PublicKey,
	}*/

	/*

	   hosts := strings.Split(*host, ",")

	   for _, h := range hosts {

	   	if ip := net.ParseIP(h); ip != nil {

	   		template.IPAddresses = append(template.IPAddresses, ip)

	   	} else {

	   		template.DNSNames = append(template.DNSNames, h)

	   	}

	   }



	   if *isCA {

	   	template.IsCA = true

	   	template.KeyUsage |= x509.KeyUsageCertSign

	   }

	*/

	//derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCert, rootCert.PublicKey, rootKey)

	template.Subject.CommonName = serverName
	template.NotBefore = time.Now()
	// Certs cannot be valid for longer than 39 mths.
	template.NotAfter = template.NotBefore.Add(39 * 30 * 24 * time.Hour)
	template.SignatureAlgorithm = rootCert.SignatureAlgorithm
	template.PublicKey = rootCert.PublicKey
	var buf [20]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, "", "", err
	}
	template.SerialNumber.SetBytes(buf[:])
	template.Issuer = rootCert.Subject
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	negotiatedProtocol := conn.ConnectionState().NegotiatedProtocol
	derBytes, err := x509.CreateCertificate(rand.Reader, template, rootCert, template.PublicKey, rootKey)
	return derBytes, negotiatedProtocol, conn.RemoteAddr().String(), err
}

type tlsProxy struct {
	root             *tls.Certificate
	root_cert        *x509.Certificate
	archive          *Archive
	writable_archive *WritableArchive
	mu               sync.Mutex
	dummy_certs_map  map[string][]byte
}

// TODO: For now, this just returns a self-signed cert using the given ServerName.
// In the future, for better HTTP/2 support, we may want to record host equivalence
// classes in the archive, where an equivalence class contains all hosts that can be
// served by the same IP. We can then run a DNS proxy that maps all hostnames in the
// same equivalence class to the same local port, which models the possibility that
// every equivalence class of hostnames can be served over the same HTTP/2 connection.
func (tp *tlsProxy) getReplayConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	h := clientHello.ServerName
	if h == "" {
		return &tls.Config{
			Certificates: []tls.Certificate{*tp.root},
		}, nil
	}

	derBytes, negotiatedProtocol, ip, err := tp.archive.FindHostTlsConfig(h)
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if err != nil || derBytes == nil {
		if _, ok := tp.dummy_certs_map[h]; !ok {
			derBytes, negotiatedProtocol, ip, err = MintDummyCertificate(h, tp.root_cert, tp.root.PrivateKey)
			if err != nil {
				return nil, err
			}
			tp.dummy_certs_map[h] = derBytes
			fmt.Errorf("ip %s", ip)
		}
		derBytes = tp.dummy_certs_map[h]
	}
	return &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{derBytes},
				PrivateKey:  tp.root.PrivateKey,
			}},
		NextProtos: buildNextProtos(negotiatedProtocol),
	}, nil
}

func buildNextProtos(negotiatedProtocol string) []string {
	if negotiatedProtocol == "h2" {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func (tp *tlsProxy) getRecordConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	h := clientHello.ServerName
	if h == "" {
		return &tls.Config{
			Certificates: []tls.Certificate{*tp.root},
		}, nil
	}
	derBytes, negotiatedProtocol, ip, err := tp.writable_archive.Archive.FindHostTlsConfig(h)
	if err == nil && derBytes != nil {
		return &tls.Config{
			Certificates: []tls.Certificate{
				tls.Certificate{
					Certificate: [][]byte{derBytes},
					PrivateKey:  tp.root.PrivateKey,
				}},
			NextProtos: buildNextProtos(negotiatedProtocol),
		}, nil
	}

	derBytes, negotiatedProtocol, ip, err = MintServerCert(h, tp.root_cert, tp.root.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create cert failed: %v", err)
	}

	tp.writable_archive.RecordTlsConfig(h, derBytes, negotiatedProtocol, ip)

	return &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{derBytes},
				PrivateKey:  tp.root.PrivateKey}},
		NextProtos: buildNextProtos(negotiatedProtocol),
	}, nil
}
