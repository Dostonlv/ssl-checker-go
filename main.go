package main

import (
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
	ValidFrom          string
	ValidUntil         string
	ValidityDays       int
	DaysLeft           int
	ValidDaysToExpire  int
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
		IssuerCountry:      cert.Issuer.Country[0],

		IssuerCN:           cert.Issuer.CommonName,
		IssuerOrganization: cert.Issuer.Organization[0],
		CertSN:             cert.SerialNumber.String(),
		CertSHA1:           fmt.Sprintf("%x", cert.SignatureAlgorithm.String()),
		CertAlgorithm:      cert.SignatureAlgorithm.String(),
		CertVersion:        cert.Version,
		CertSANs:           cert.DNSNames,
		CertExpired:        cert.NotAfter.Before(time.Now()),
		CertValid:          cert.NotBefore.Before(time.Now()) && cert.NotAfter.After(time.Now()),
		ValidFrom:          cert.NotBefore.Format("02.01.2006"),
		ValidUntil:         cert.NotAfter.Format("02.01.2006"),
		ValidityDays:       int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24),
		DaysLeft:           int(cert.NotAfter.Sub(time.Now()).Hours() / 24),
		ValidDaysToExpire:  int(cert.NotAfter.Sub(time.Now()).Hours() / 24),
	}

	fmt.Println(CertInfo.IssuedOrganization)

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
