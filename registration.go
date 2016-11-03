// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
)

// Registration represents a single enrolment or pairing between an
// application and a token. The keyHandle, publicKey and usage count must be stored
type Registration struct {
	// Raw KeyHandle
	KeyHandle string
	// Base64 encoded ASN1 public key
	PublicKey string
	// Usage counter
	Counter uint
	// Base64 encoded PEM certificate
	Certificate string
}

// Raw registration object for internal use
type registrationRaw struct {
	// Data that should be stored
	KeyHandle []byte
	PublicKey ecdsa.PublicKey
	Counter   uint32

	// AttestationCert can be nil for Authenticate requests.
	AttestationCert *x509.Certificate

	// Raw serialized registration data as received from the token.
	raw []byte
}

// Implements encoding.BinaryMarshaler.
func (r *registrationRaw) UnmarshalBinary(data []byte) error {
	reg, _, err := parseRegistration(data)
	if err != nil {
		return err
	}
	*r = *reg
	return nil
}

// Implements encoding.BinaryUnmarshaler.
func (r *registrationRaw) MarshalBinary() ([]byte, error) {
	return r.raw, nil
}

// Unpacks a Registration structure to registrationRaw for internal use
func (reg *registrationRaw) ToRegistration() *Registration {

	// Convert to strings
	keyHandleString := encodeBase64(reg.KeyHandle)
	publicKeyString := encodeBase64(elliptic.Marshal(reg.PublicKey.Curve, reg.PublicKey.X, reg.PublicKey.Y))
	certString := encodeBase64(reg.AttestationCert.Raw)

	// Create struct
	cleanReg := Registration{
		KeyHandle:   keyHandleString,
		PublicKey:   publicKeyString,
		Certificate: certString,
		Counter:     uint(reg.Counter),
	}

	return &cleanReg
}

// Packs a registrationRaw structure to a user friendly Registration structure
func (reg *registrationRaw) FromRegistration(r Registration) error {

	// Convert and set fields
	reg.KeyHandle, _ = decodeBase64(r.KeyHandle)

	// Public key
	publicKeyDecoded, err := decodeBase64(r.PublicKey)

	reg.PublicKey.X, reg.PublicKey.Y = elliptic.Unmarshal(elliptic.P256(), publicKeyDecoded)
	reg.PublicKey.Curve = elliptic.P256()

	// Attestation certificate
	certStringDecoded, err := decodeBase64(r.Certificate)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certStringDecoded)
	if err != nil {
		return err
	}
	reg.AttestationCert = cert

	// Counter
	reg.Counter = uint32(r.Counter)

	return nil
}
