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
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
    "reflect"
    "fmt"
)

const u2fVersion = "U2F_V2"
const timeout = 5 * time.Minute

// Decode websafe base64
func decodeBase64(s string) ([]byte, error) {
	for i := 0; i < len(s)%4; i++ {
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// Encode websafe base64
func encodeBase64(buf []byte) string {
	s := base64.URLEncoding.EncodeToString(buf)
	return strings.TrimRight(s, "=")
}

// Verify client data object
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

// Helper to set a field of type string
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

// Helper to get a field of type string
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

// Helper to set a field of type int
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

// Helper to get a field of type int
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

