// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// Registration request configuration
type RegistrationConfig struct {
	// SkipAttestationVerify controls whether the token attestation
	// certificate should be verified on registration. Ideally it should
	// always be verified. However, there is currently no public list of
	// trusted attestation root certificates so it may be necessary to skip.
	SkipAttestationVerify bool
}

// getRegisterRequest creates a RegisterRequest from a given challenge
func (c *Challenge) newRegisterRequest() *registerRequest {
	var rr registerRequest
	rr.Version = u2fVersion
	rr.AppID = c.AppID
	rr.Challenge = encodeBase64(c.Challenge)
	return &rr
}

// RegisterRequest builds a registration request from a challenge
// This must be provided with already registered key handles
func (c *Challenge) RegisterRequest() *RegisterRequestMessage {
	var m RegisterRequestMessage

	// Set the AppID
	m.AppID = c.AppID

	// Create a registration request
	// Note that this can contain N requests, but we only need one
	// And to change this would remove the 1-1 challenge/request mapping
	// which is convenient for now
	registerRequest := c.newRegisterRequest()
	m.RegisterRequests = append(m.RegisterRequests, *registerRequest)

	// Add existing keys to request message
	for _, r := range c.RegisteredKeys {
		key := registeredKey{
			Version:   u2fVersion,
			KeyHandle: encodeBase64([]byte(r.KeyHandle))}
		m.RegisteredKeys = append(m.RegisteredKeys, key)
	}

	// Return request message (for client)
	return &m
}

// Register validates a RegisterResponse message to enrol a new token against the provided challenge
// An error is returned if any part of the response fails to validate.
// The returned Registration should be stored by the caller.
func (c *Challenge) Register(resp RegisterResponse, config *RegistrationConfig) (*Registration, error) {
	if config == nil {
		config = &RegistrationConfig{}
	}

	if time.Now().Sub(c.Timestamp) > timeout {
		return nil, errors.New("u2f: challenge has expired")
	}

	regData, err := decodeBase64(resp.RegistrationData)
	if err != nil {
		return nil, err
	}

	clientData, err := decodeBase64(resp.ClientData)
	if err != nil {
		return nil, err
	}

	reg, sig, err := parseRegistration(regData)
	if err != nil {
		return nil, err
	}

	if err := verifyClientData(clientData, *c); err != nil {
		return nil, err
	}

	if err := verifyAttestationCert(*reg, config); err != nil {
		return nil, err
	}

	if err := verifyRegistrationSignature(*reg, sig, c.AppID, clientData); err != nil {
		return nil, err
	}

	cleanReg := Registration{}
	if err := reg.MarsalStruct(cleanReg); err != nil {
		return nil, err
	}

	return cleanReg, nil
}

func parseRegistration(buf []byte) (*RegistrationRaw, []byte, error) {
	if len(buf) < 1+65+1+1+1 {
		return nil, nil, errors.New("u2f: data is too short")
	}

	var r RegistrationRaw
	r.raw = buf

	if buf[0] != 0x05 {
		return nil, nil, errors.New("u2f: invalid reserved byte")
	}
	buf = buf[1:]

	x, y := elliptic.Unmarshal(elliptic.P256(), buf[:65])
	if x == nil {
		return nil, nil, errors.New("u2f: invalid public key")
	}
	r.PublicKey.Curve = elliptic.P256()
	r.PublicKey.X = x
	r.PublicKey.Y = y
	buf = buf[65:]

	khLen := int(buf[0])
	buf = buf[1:]
	if len(buf) < khLen {
		return nil, nil, errors.New("u2f: invalid key handle")
	}
	r.KeyHandle = buf[:khLen]
	buf = buf[khLen:]

	// The length of the x509 cert isn't specified so it has to be inferred
	// by parsing. We can't use x509.ParseCertificate yet because it returns
	// an error if there are any trailing bytes. So parse raw asn1 as a
	// workaround to get the length.
	sig, err := asn1.Unmarshal(buf, &asn1.RawValue{})
	if err != nil {
		return nil, nil, err
	}

	buf = buf[:len(buf)-len(sig)]
	cert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, nil, err
	}
	r.AttestationCert = cert

	r.Counter = 0

	return &r, sig, nil
}

func verifyAttestationCert(r RegistrationRaw, config *RegistrationConfig) error {
	if config.SkipAttestationVerify {
		return nil
	}

	opts := x509.VerifyOptions{Roots: roots}
	_, err := r.AttestationCert.Verify(opts)
	return err
}

func verifyRegistrationSignature(
	r RegistrationRaw, signature []byte, appid string, clientData []byte) error {

	appParam := sha256.Sum256([]byte(appid))
	challenge := sha256.Sum256(clientData)

	buf := []byte{0}
	buf = append(buf, appParam[:]...)
	buf = append(buf, challenge[:]...)
	buf = append(buf, r.KeyHandle...)
	pk := elliptic.Marshal(r.PublicKey.Curve, r.PublicKey.X, r.PublicKey.Y)
	buf = append(buf, pk...)

	return r.AttestationCert.CheckSignature(
		x509.ECDSAWithSHA256, buf, signature)
}
