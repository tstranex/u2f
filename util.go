// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.

package u2f

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const u2fVersion = "U2F_V2"

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

func genChallenge() (string, error) {
	challenge := make([]byte, 32)
	n, err := rand.Read(challenge)
	if err != nil {
		return "", err
	}
	if n != 32 {
		return "", errors.New("u2f: unable to generate random bytes")
	}
	return encodeBase64(challenge), nil
}

func verifyClientData(client_data []byte, req_challenge string, trusted_facets TrustedFacets) error {
	var cd ClientData
	if err := json.Unmarshal(client_data, &cd); err != nil {
		return err
	}

	found_facet_id := false
	for _, facet_id := range trusted_facets.Ids {
		if facet_id == cd.Origin {
			found_facet_id = true
			break
		}
	}
	if !found_facet_id {
		return errors.New("u2f: untrusted facet id")
	}

	if len(req_challenge) != len(cd.Challenge) ||
		subtle.ConstantTimeCompare([]byte(req_challenge), []byte(cd.Challenge)) != 1 {
		return errors.New("u2f: challenge does not match")
	}

	return nil
}
