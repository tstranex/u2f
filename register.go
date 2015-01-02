// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.

package u2f

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// RegisterRequest creates a request to enrol a new token.
func (c *Challenge) RegisterRequest() *RegisterRequest {
	var rr RegisterRequest
	rr.Version = u2fVersion
	rr.AppId = c.AppId
	rr.Challenge = encodeBase64(c.Challenge)
	return &rr
}

// Registration represents a single enrolment or pairing between an
// application and a token. This data will typically be stored in a database.
type Registration struct {
	KeyHandle []byte
	PubKey    ecdsa.PublicKey
	Counter   uint32

	// AttestationCert can be nil for Authenticate requests.
	AttestationCert *x509.Certificate

	signature []byte
}

// Register validates a RegisterResponse message to enrol a new token.
// An error is returned if any part of the response fails to validate.
// The returned Registration should be stored by the caller.
func Register(resp RegisterResponse, c Challenge) (*Registration, error) {
	if time.Now().Sub(c.Timestamp) > timeout {
		return nil, errors.New("u2f: challenge has expired")
	}

	reg_data, err := decodeBase64(resp.RegistrationData)
	if err != nil {
		return nil, err
	}

	client_data, err := decodeBase64(resp.ClientData)
	if err != nil {
		return nil, err
	}

	reg, err := parseRegistration(reg_data)
	if err != nil {
		return nil, err
	}

	if err := verifyClientData(client_data, c); err != nil {
		return nil, err
	}

	if err := verifyAttestationCert(*reg); err != nil {
		return nil, err
	}

	if err := verifyRegistrationSignature(*reg, c.AppId, client_data); err != nil {
		return nil, err
	}

	return reg, nil
}

func parseRegistration(buf []byte) (*Registration, error) {
	if len(buf) < 1+65+1+1+1 {
		return nil, errors.New("u2f: data is too short")
	}

	if buf[0] != 0x05 {
		return nil, errors.New("u2f: invalid reserved byte")
	}
	buf = buf[1:]

	var r Registration

	x, y := elliptic.Unmarshal(elliptic.P256(), buf[:65])
	if x == nil {
		return nil, errors.New("u2f: invalid public key")
	}
	r.PubKey.Curve = elliptic.P256()
	r.PubKey.X = x
	r.PubKey.Y = y
	buf = buf[65:]

	kh_len := int(buf[0])
	buf = buf[1:]
	if len(buf) < kh_len {
		return nil, errors.New("u2f: invalid key handle")
	}
	r.KeyHandle = buf[:kh_len]
	buf = buf[kh_len:]

	// The length of the x509 cert isn't specified so it has to be inferred
	// by parsing. We can't use x509.ParseCertificate yet because it returns
	// an error if there are any trailing bytes. So parse raw asn1 as a
	// workaround to get the length.
	rest, err := asn1.Unmarshal(buf, &asn1.RawValue{})
	if err != nil {
		return nil, err
	}
	r.signature = rest

	buf = buf[:len(buf)-len(rest)]
	cert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, err
	}
	r.AttestationCert = cert

	return &r, nil
}

func verifyAttestationCert(r Registration) error {
	opts := x509.VerifyOptions{Roots: roots}
	_, err := r.AttestationCert.Verify(opts)
	return err
}

func verifyRegistrationSignature(
	r Registration, appid string, client_data []byte) error {

	app_param := sha256.Sum256([]byte(appid))
	challenge := sha256.Sum256(client_data)

	buf := []byte{0}
	buf = append(buf, app_param[:]...)
	buf = append(buf, challenge[:]...)
	buf = append(buf, r.KeyHandle...)
	pk := elliptic.Marshal(r.PubKey.Curve, r.PubKey.X, r.PubKey.Y)
	buf = append(buf, pk...)

	return r.AttestationCert.CheckSignature(
		x509.ECDSAWithSHA256, buf, r.signature)
}
