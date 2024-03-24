package main

import (
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
