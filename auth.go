// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)


// Convenience message to wrap a U2F Signature Request
// This contains a single challenge to be signed by any of the registered keys
type SignRequestMessage struct {
	AppID     string `json:"appId"`
	Challenge string `json:'challenge'`
	RegisteredKeys []RegisteredKey
	registrations  []Registration
	challenge *Challenge
}


// SignRequest creates a request to initiate an authentication.
func (c *Challenge) getSignRequest(reg Registration) *SignRequest {
	var sr SignRequest
	sr.Version = u2fVersion
	sr.KeyHandle = encodeBase64(reg.KeyHandle)
	sr.AppID = c.AppID
	sr.Challenge = encodeBase64(c.Challenge)
	return &sr
}

func (c *Challenge) SignRequest(registrations []Registration) *SignRequestMessage {
	var m SignRequestMessage

	// Build public message fields
	m.AppID = c.AppID
	m.Challenge = encodeBase64(c.Challenge)

	// Add existing keys to request message
	for _, r := range registrations {
		registeredKey := RegisteredKey{
			Version: u2fVersion, 
			KeyHandle: encodeBase64(r.KeyHandle)}
		m.RegisteredKeys = append(m.RegisteredKeys, registeredKey)
	}

	// Save registrations for later checking
	m.registrations = registrations
	m.challenge = c

	return &m
}

func (sr *SignRequestMessage) Authenticate(resp SignResponse, counter uint32) (newCounter uint32, err error) {

	// Find appropriate registration
	var reg *Registration = nil
	for _, r := range sr.registrations {
		if resp.KeyHandle == encodeBase64(r.KeyHandle) {
			reg = &r
		}
	}
	if reg == nil {
		return 0, errors.New("u2f: wrong key handle")
	}

	return reg.Authenticate(resp, *sr.challenge, counter)
}

// Authenticate validates a SignResponse authentication response.
// An error is returned if any part of the response fails to validate.
// The latest counter value is returned, which the caller should store.
func (reg *Registration) Authenticate(resp SignResponse, c Challenge, counter uint32) (newCounter uint32, err error) {
	if time.Now().Sub(c.Timestamp) > timeout {
		return 0, errors.New("u2f: challenge has expired")
	}

	if resp.KeyHandle != encodeBase64(reg.KeyHandle) {
		return 0, errors.New("u2f: wrong key handle")
	}

	sigData, err := decodeBase64(resp.SignatureData)
	if err != nil {
		return 0, err
	}

	clientData, err := decodeBase64(resp.ClientData)
	if err != nil {
		return 0, err
	}

	ar, err := parseSignResponse(sigData)
	if err != nil {
		return 0, err
	}

	if ar.Counter < counter {
		return 0, errors.New("u2f: counter not increasing")
	}

	if err := verifyClientData(clientData, c); err != nil {
		return 0, err
	}

	if err := verifyAuthSignature(*ar, &reg.PubKey, c.AppID, clientData); err != nil {
		return 0, err
	}

	if !ar.UserPresenceVerified {
		return 0, errors.New("u2f: user was not present")
	}

	return ar.Counter, nil
}

type ecdsaSig struct {
	R, S *big.Int
}

type authResp struct {
	UserPresenceVerified bool
	Counter              uint32
	sig                  ecdsaSig
	raw                  []byte
}

func parseSignResponse(sd []byte) (*authResp, error) {
	if len(sd) < 5 {
		return nil, errors.New("u2f: data is too short")
	}

	var ar authResp

	userPresence := sd[0]
	if userPresence|1 != 1 {
		return nil, errors.New("u2f: invalid user presence byte")
	}
	ar.UserPresenceVerified = userPresence == 1

	ar.Counter = uint32(sd[1])<<24 | uint32(sd[2])<<16 | uint32(sd[3])<<8 | uint32(sd[4])

	ar.raw = sd[:5]

	rest, err := asn1.Unmarshal(sd[5:], &ar.sig)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("u2f: trailing data")
	}

	return &ar, nil
}

func verifyAuthSignature(ar authResp, pubKey *ecdsa.PublicKey, appID string, clientData []byte) error {
	appParam := sha256.Sum256([]byte(appID))
	challenge := sha256.Sum256(clientData)

	var buf []byte
	buf = append(buf, appParam[:]...)
	buf = append(buf, ar.raw...)
	buf = append(buf, challenge[:]...)
	hash := sha256.Sum256(buf)

	if !ecdsa.Verify(pubKey, hash[:], ar.sig.R, ar.sig.S) {
		return errors.New("u2f: invalid signature")
	}

	return nil
}
