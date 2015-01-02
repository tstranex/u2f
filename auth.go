package u2f

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

func NewSignRequest(key_handle []byte, app_id string) (*SignRequest, error) {
	challenge, err := genChallenge()
	if err != nil {
		return nil, err
	}

	var sr SignRequest
	sr.Version = u2fVersion
	sr.KeyHandle = encodeBase64(key_handle)
	sr.AppId = app_id
	sr.Challenge = challenge
	return &sr, nil
}

func VerifySignResponse(resp SignResponse, req SignRequest, req_timestamp time.Time, reg Registration, trusted_facets TrustedFacets, counter uint32) (uint32, error) {

	if time.Now().Sub(req_timestamp) > 5*time.Minute {
		return 0, errors.New("u2f: challenge has expired")
	}
	if resp.KeyHandle != req.KeyHandle {
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

	if ar.Counter < counter {
		return 0, errors.New("u2f: counter not increasing")
	}

	if err := verifyClientData(client_data, req.Challenge, trusted_facets); err != nil {
		return 0, err
	}

	if err := verifyAuthSignature(*ar, &reg.PubKey, req.AppId, client_data); err != nil {
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
