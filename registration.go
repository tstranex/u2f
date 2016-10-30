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
    // Data that should be stored
    KeyHandle []byte
    PubKey    ecdsa.PublicKey
    Counter   uint32

    // AttestationCert can be nil for Authenticate requests.
    AttestationCert *x509.Certificate

    // Raw serialized registration data as received from the token.
    raw []byte
}

// Implements encoding.BinaryMarshaler.
func (r *Registration) UnmarshalBinary(data []byte) error {
    reg, _, err := parseRegistration(data)
    if err != nil {
        return err
    }
    *r = *reg
    return nil
}

// Implements encoding.BinaryUnmarshaler.
func (r *Registration) MarshalBinary() ([]byte, error) {
    return r.raw, nil
}


func (reg *Registration) MarshalStruct(i interface{}) error {
    r := reflect.ValueOf(i).Elem()

    // Check the interface is a struct
    if r.Kind() != reflect.Struct {
        return fmt.Errorf("Interface is not a struct (type is: %s)", r.Kind())
    }

    err := reflectSetFieldString(i, "KeyHandle", string(reg.KeyHandle))
    if err != nil {
        return err
    }

    publicKeyString := encodeBase64(elliptic.Marshal(reg.PubKey.Curve, reg.PubKey.X, reg.PubKey.Y))
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

func (reg *Registration) UnmarshalStruct(i interface{}) error {
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

    reg.PubKey.X, reg.PubKey.Y = elliptic.Unmarshal(elliptic.P256(), publicKeyDecoded)
    reg.PubKey.Curve = elliptic.P256()

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

func reflectSetFieldString(i interface{}, name string, value string) error {
    r := reflect.ValueOf(i).Elem()

    field := r.FieldByName(name)
    if field.Kind() == reflect.Invalid {
        return fmt.Errorf("Cannot find field: %s", name)
    }
    if field.Kind() != reflect.String {
        return fmt.Errorf("Invalid field type: %s field: %s", field.Kind(), name)
    }
    if !field.CanSet() {
        return fmt.Errorf("Cannot set field: %s", name)
    }
    field.SetString(value)

    return nil
}

func reflectGetFieldString(i interface{}, name string) (string, error) {
    r := reflect.ValueOf(i).Elem()

    field := r.FieldByName(name)
    if field.Kind() == reflect.Invalid {
        return "", fmt.Errorf("Cannot find field: %s", name)
    }
    if field.Kind() != reflect.String {
        return "", fmt.Errorf("Invalid field type: %s field: %s", field.Kind(), name)
    }

    return field.String(), nil
}

func reflectSetFieldUint(i interface{}, name string, value uint32) error {
    r := reflect.ValueOf(i).Elem()

    field := r.FieldByName(name)
    if field.Kind() == reflect.Invalid {
        return fmt.Errorf("Cannot find field: %s", name)
    }
    if field.Kind() != reflect.Uint {
        return fmt.Errorf("Invalid field type: %s field: %s", field.Kind(), name)
    }
    if !field.CanSet() {
        return fmt.Errorf("Cannot set field: %s", name)
    }
    field.SetUint(uint64(value))

    return nil
}

func reflectGetFieldUint(i interface{}, name string) (uint, error) {
    r := reflect.ValueOf(i).Elem()

    field := r.FieldByName(name)
    if field.Kind() == reflect.Invalid {
        return 0, fmt.Errorf("Cannot find field: %s", name)
    }
    if field.Kind() != reflect.Uint {
        return 0, fmt.Errorf("Invalid field type: %s field: %s", field.Kind(), name)
    }

    return uint(field.Uint()), nil
}
