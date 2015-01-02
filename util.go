// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.

/*
Package u2f implements the server-side parts of the
FIDO Universal 2nd Factor (U2F) specification.

Applications will usually persist Challenge and Registration objects in a
database.

To enrol a new token:

    app_id := "http://localhost"
    c, _ := NewChallenge(app_id, []string{app_id})
    req, _ := c.RegisterRequest()
    // Send the request to the browser.
    var resp RegisterResponse
    // Read resp from the browser.
    reg, err := Register(resp, c)
    if err != nil {
         // Registration failed.
    }
    // Store reg in the database.

To perform an authentication:

    var reg Registration
    // Fetch reg from the database.
    c, _ := NewChallenge(app_id, []string{app_id})
    req, _ := c.SignRequest(reg)
    // Send the request to the browser.
    var resp SignResponse
    // Read resp from the browser.
    new_counter, err := reg.Authenticate(resp, c)
    if err != nil {
        // Authentication failed.
    }
    reg.Counter = new_counter
    // Store updated Registration in the database.

The FIDO U2F specification can be found here:
https://fidoalliance.org/specifications/download
*/
package u2f

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

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
	Challenge     []byte
	Timestamp     time.Time
	AppId         string
	TrustedFacets []string
}

// NewChallange generates a challenge for the given application.
func NewChallenge(app_id string, trusted_facets []string) (*Challenge, error) {
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
	c.AppId = app_id
	c.TrustedFacets = trusted_facets
	return &c, nil
}

func verifyClientData(client_data []byte, challenge Challenge) error {
	var cd ClientData
	if err := json.Unmarshal(client_data, &cd); err != nil {
		return err
	}

	found_facet_id := false
	for _, facet_id := range challenge.TrustedFacets {
		if facet_id == cd.Origin {
			found_facet_id = true
			break
		}
	}
	if !found_facet_id {
		return errors.New("u2f: untrusted facet id")
	}

	c := encodeBase64(challenge.Challenge)
	if len(c) != len(cd.Challenge) ||
		subtle.ConstantTimeCompare([]byte(c), []byte(cd.Challenge)) != 1 {
		return errors.New("u2f: challenge does not match")
	}

	return nil
}
