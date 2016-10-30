// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/x509"
    "reflect"
    "fmt"
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
    AttestationCert string
}

// Raw registration object for internal use
type RegistrationRaw struct {
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
func (r *RegistrationRaw) UnmarshalBinary(data []byte) error {
    reg, _, err := parseRegistration(data)
    if err != nil {
        return err
    }
    *r = *reg
    return nil
}

// Implements encoding.BinaryUnmarshaler.
func (r *RegistrationRaw) MarshalBinary() ([]byte, error) {
    return r.raw, nil
}

// Marshals a Registration structure to a provided interface
func (reg *RegistrationRaw) MarshalStruct(i interface{}) error {
    r := reflect.ValueOf(i).Elem()

    // Check the interface is a struct
    if r.Kind() != reflect.Struct {
        return fmt.Errorf("Interface is not a struct (type is: %s)", r.Kind())
    }

    err := reflectSetFieldString(i, "KeyHandle", string(reg.KeyHandle))
    if err != nil {
        return err
    }

    publicKeyString := encodeBase64(elliptic.Marshal(reg.PublicKey.Curve, reg.PublicKey.X, reg.PublicKey.Y))
    err = reflectSetFieldString(i, "PublicKey", publicKeyString)
    if err != nil {
        return err
    }

    certString := encodeBase64(reg.AttestationCert.Raw)
    err = reflectSetFieldString(i, "Certificate", certString)
    if err != nil {
        return err
    }

    err = reflectSetFieldUint(i, "Counter", reg.Counter)
    if err != nil {
        return err
    }

    return err
}

// Unmarshals a Registration structure from a provided interface
func (reg *RegistrationRaw) UnmarshalStruct(i interface{}) error {
    r := reflect.ValueOf(i).Elem()

    // Check the interface is a struct
    if r.Kind() != reflect.Struct {
        return fmt.Errorf("Interface is not a struct (type is: %s)", r.Kind())
    }

    // Key handle
    keyHandleString, err := reflectGetFieldString(i, "KeyHandle")
    if err != nil {
        return err
    }
    reg.KeyHandle = []byte(keyHandleString)

    // Public key
    publicKeyString, err := reflectGetFieldString(i, "PublicKey")
    if err != nil {
        return err
    }

    publicKeyDecoded, err := decodeBase64(publicKeyString)
    if err != nil {
        return err
    }

    reg.PublicKey.X, reg.PublicKey.Y = elliptic.Unmarshal(elliptic.P256(), publicKeyDecoded)
    reg.PublicKey.Curve = elliptic.P256()

    // Attestation certificate
    certString, err := reflectGetFieldString(i, "Certificate")
    if err != nil {
        return err
    }
    certStringDecoded, err := decodeBase64(certString)
    if err != nil {
        return err
    }
    cert, err := x509.ParseCertificate(certStringDecoded)
    if err != nil {
        return err
    }

    reg.AttestationCert = cert

    Counter, err := reflectGetFieldUint(i, "Counter")
    if err != nil {
        return err
    }

    reg.Counter = uint32(Counter)

    return nil
}
