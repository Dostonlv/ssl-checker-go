package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"os"
	"time"
)

type CertInfo struct {
	Host               string
	Status             string
	ResponseTime       time.Duration
	ResolvedIP         string
	IssuedTo           string
	IssuedOrganization string
	IssuerCountry      string
	IssuerCN           string
	IssuerOrganization string
	CertSN             string
	CertSHA1           string
	CertAlgorithm      string
	CertVersion        int
	CertSANs           []string
	CertExpired        bool
	CertValid          bool
	ValidFrom          time.Time
	ValidUntil         time.Time
	ValidityDays       int
	DaysLeft           int
	ValidDaysToExpire  int
	HSTSHeaderEnabled  bool
}

func main() {
	var server = "akihito.uz"
	var domainName = "akihito.uz"
	port := "443"
	if addr, err := net.LookupIP(server); err == nil {
		server = addr[0].String()
	}

	hostname := server

	server += ":" + port

	cert, err := getCert(server, hostname)
	if err != nil {
		fmt.Println("Error getting cert: ", err)
		os.Exit(1)
	}

	var CertInfo = &CertInfo{
		Host:               domainName,
		Status:             "OK",
		ResponseTime:       time.Duration(0),
		ResolvedIP:         server,
		IssuedOrganization: IsEmpty(cert.Subject.Organization),
		// IssuerCountry:      cert.Subject.Country[0],

		IssuerCN:           cert.Issuer.CommonName,
		IssuerOrganization: cert.Issuer.Organization[0],
		CertSN:             cert.SerialNumber.String(),
		CertSHA1:           fmt.Sprintf("%x", cert.SignatureAlgorithm.String()),
	}
	fingerprint := md5.Sum(cert.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	fmt.Printf("Fingerprint for  %s", buf.String())

	fmt.Println(CertInfo.CertSHA1)
}

func getCert(server, hostname string) (*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	conn, err := tls.Dial("tcp", server, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates[0], nil
}

func IsEmpty(s any) string {
	if len(s.([]string)) == 0 {
		return "N/A"
	}
	return s.(string)
}
