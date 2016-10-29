// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

/*
Package u2f implements the server-side parts of the
FIDO Universal 2nd Factor (U2F) specification.

Applications will need to persist Challenge and Registration objects.

Request Enrolment
    // Fetch registration entries from the database
    var registeredKeys []u2f.Registration

    app_id := "http://localhost"

    // Generate registration request
    c1, _ := u2f.NewChallenge(app_id, []string{app_id}, registeredKeys)
    req, _ := c1.RegisterRequest()

    // Send request to browser
    ...

    // Save challenge to session
    ...

Check Enrolment
    // Read challenge from session
    var c1 u2f.Challenge

    // Read response from the browser
    var resp u2f.RegisterResponse

    // Perform registration
    reg, err := c1.Register(resp)
    if err != nil {
        // Registration failed.
    }

    // Store registration in the database against a user
    ...


Request Authentication
    // Fetch registration entries for a user from the database
    var registeredKeys []Registration

    app_id := "http://localhost"

    // Generate authentication request
    c2, _ := u2f.NewChallenge(app_id, []string{app_id}, registeredKeys)
    req, _ := c2.SignRequest()

    // Send request to browser
    ...

    // Save challenge to session
    ...


Check Authentication
    // Read challenge from session
    var c1 u2f.Challenge

    // Read response from the browser
    var resp SignResponse

    // Perform authentication
    reg, err := c2.Authenticate(resp)
    if err != nil {
        // Authentication failed.
    }

    // Store updated registration (use counter) in the database
    ...


The FIDO U2F specification can be found here:
https://fidoalliance.org/specifications/download
*/
package u2f

import (
	"crypto/rand"
	"crypto/subtle"
    "crypto/elliptic"
    "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
    "fmt"
)

import "reflect"

const u2fVersion = "U2F_V2"
const timeout = 5 * time.Minute

func decodeBase64(s string) ([]byte, error) {
	for i := 0; i < len(s)%4; i++ {
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func encodeBase64(buf []byte) string {
	s := base64.URLEncoding.EncodeToString(buf)
	return strings.TrimRight(s, "=")
}

// Challenge represents a single transaction between the server and
// authenticator. This data will typically be stored in a database.
type Challenge struct {
	Challenge      []byte
	Timestamp      time.Time
	AppID          string
	TrustedFacets  []string
	RegisteredKeys []Registration
}

// NewChallenge generates a challenge for the given application, trusted facets, and registered keys
// This challenge can then be used to generate and validate registration or authorization requests
func NewChallenge(appID string, trustedFacets []string, registeredKeys []Registration) (*Challenge, error) {
	challenge := make([]byte, 32)
	n, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, errors.New("u2f: unable to generate random bytes")
	}

	var c Challenge
	c.Challenge = challenge
	c.Timestamp = time.Now()
	c.AppID = appID
	c.TrustedFacets = trustedFacets
	c.RegisteredKeys = registeredKeys

	return &c, nil
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

func verifyClientData(clientData []byte, challenge Challenge) error {
	var cd ClientData
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return err
	}

	foundFacetID := false
	for _, facetID := range challenge.TrustedFacets {
		if facetID == cd.Origin {
			foundFacetID = true
			break
		}
	}
	if !foundFacetID {
		return errors.New("u2f: untrusted facet id")
	}

	c := encodeBase64(challenge.Challenge)
	if len(c) != len(cd.Challenge) ||
		subtle.ConstantTimeCompare([]byte(c), []byte(cd.Challenge)) != 1 {
		return errors.New("u2f: challenge does not match")
	}

	return nil
}
