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

func NewRegisterRequest(app_id string) (*RegisterRequest, error) {
	challenge, err := genChallenge()
	if err != nil {
		return nil, err
	}

	var rr RegisterRequest
	rr.Version = u2fVersion
	rr.AppId = app_id
	rr.Challenge = challenge
	return &rr, nil
}

func VerifyRegisterResponse(resp RegisterResponse, req RegisterRequest, req_timestamp time.Time, trusted_facets TrustedFacets) (*Registration, error) {

	if time.Now().Sub(req_timestamp) > 5*time.Minute {
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

	if err := verifyClientData(client_data, req.Challenge, trusted_facets); err != nil {
		return nil, err
	}

	if err := verifyAttestationCert(*reg); err != nil {
		return nil, err
	}

	if err := verifySignature(*reg, req.AppId, client_data); err != nil {
		return nil, err
	}

	return reg, nil
}

type Registration struct {
	PubKey          ecdsa.PublicKey
	KeyHandle       []byte
	AttestationCert *x509.Certificate
	Signature       []byte
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
	r.Signature = rest

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

func verifySignature(r Registration, appid string, client_data []byte) error {
	app_param := sha256.Sum256([]byte(appid))
	challenge := sha256.Sum256(client_data)

	buf := []byte{0}
	buf = append(buf, app_param[:]...)
	buf = append(buf, challenge[:]...)
	buf = append(buf, r.KeyHandle...)
	pk := elliptic.Marshal(r.PubKey.Curve, r.PubKey.X, r.PubKey.Y)
	buf = append(buf, pk...)

	return r.AttestationCert.CheckSignature(
		x509.ECDSAWithSHA256, buf, r.Signature)
}
