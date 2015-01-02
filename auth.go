// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.

package u2f

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// SignRequest creates a request to initiate an authentication.
func (c *Challenge) SignRequest(reg Registration) *SignRequest {
	var sr SignRequest
	sr.Version = u2fVersion
	sr.KeyHandle = encodeBase64(reg.KeyHandle)
	sr.AppId = c.AppId
	sr.Challenge = encodeBase64(c.Challenge)
	return &sr
}

// Authenticate validates a SignResponse authentication response.
// An error is returned if any part of the response fails to validate.
// The latest counter value is returned, which the caller should store.
func (reg *Registration) Authenticate(resp SignResponse, c Challenge) (new_counter uint32, err error) {
	if time.Now().Sub(c.Timestamp) > timeout {
		return 0, errors.New("u2f: challenge has expired")
	}
	if resp.KeyHandle != encodeBase64(reg.KeyHandle) {
		return 0, errors.New("u2f: wrong key handle")
	}

	sig_data, err := decodeBase64(resp.SignatureData)
	if err != nil {
		return 0, err
	}

	client_data, err := decodeBase64(resp.ClientData)
	if err != nil {
		return 0, err
	}

	ar, err := parseSignResponse(sig_data)
	if err != nil {
		return 0, err
	}

	if ar.Counter < reg.Counter {
		return 0, errors.New("u2f: counter not increasing")
	}

	if err := verifyClientData(client_data, c); err != nil {
		return 0, err
	}

	if err := verifyAuthSignature(*ar, &reg.PubKey, c.AppId, client_data); err != nil {
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

	user_presence := sd[0]
	if user_presence|1 != 1 {
		return nil, errors.New("u2f: invalid user presence byte")
	}
	ar.UserPresenceVerified = user_presence == 1

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

func verifyAuthSignature(ar authResp, pub_key *ecdsa.PublicKey, app_id string, client_data []byte) error {
	app_param := sha256.Sum256([]byte(app_id))
	challenge := sha256.Sum256(client_data)

	buf := make([]byte, 0)
	buf = append(buf, app_param[:]...)
	buf = append(buf, ar.raw...)
	buf = append(buf, challenge[:]...)
	hash := sha256.Sum256(buf)

	if !ecdsa.Verify(pub_key, hash[:], ar.sig.R, ar.sig.S) {
		return errors.New("u2f: invalid signature")
	}

	return nil
}
