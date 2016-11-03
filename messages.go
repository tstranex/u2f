// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
	"encoding/json"
)

// U2F message transport types
const U2FTransportBT string = "bt"
const U2FTransportBLE string = "ble"
const U2FTransportNFC string = "nfc"
const U2FTransportUSB string = "usb"

// JwkKey represents a public key used by a browser for the Channel ID TLS
// extension.
type JwkKey struct {
	KTy string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ClientData as defined by the FIDO U2F Raw Message Formats specification.
type ClientData struct {
	Typ          string          `json:"typ"`
	Challenge    string          `json:"challenge"`
	Origin       string          `json:"origin"`
	CIDPublicKey json.RawMessage `json:"cid_pubkey"`
}

// RegisterRequest defines a registration challenge to the token
type registerRequest struct {
	Version   string `json:"version"`
	Challenge string `json:"challenge"`
	AppID     string `json:"appId,omitempty"`
}

// RegisteredKey represents a U2F key registered to the account
type registeredKey struct {
	Version    string `json:"version"`
	KeyHandle  string `json:"keyHandle"`
	Transports string `json:"transports,omitempty"`
	AppID      string `json:"appId,omitempty"`
}

// Represents U2F Registration Request
// This message is passed to the browser for registration
type RegisterRequestMessage struct {
	AppID            string            `json:"appId"`
	RegisterRequests []registerRequest `json:"registerRequests"`
	RegisteredKeys   []registeredKey   `json:"registeredKeys"`
}

// RegisterResponse is the structure returned by the token/u2f implementation
type RegisterResponse struct {
	RegistrationData string `json:"registrationData"`
	ClientData       string `json:"clientData"`
}

// Represents a U2F Signature Request.
// This message is passed to the browser for authentication
type SignRequestMessage struct {
	AppID          string          `json:"appId"`
	Challenge      string          `json:"challenge"`
	RegisteredKeys []registeredKey `json:"registeredKeys"`
}

// SignResponse as defined by the FIDO U2F Javascript API.
type SignResponse struct {
	KeyHandle     string `json:"keyHandle"`
	SignatureData string `json:"signatureData"`
	ClientData    string `json:"clientData"`
}

// TrustedFacets as defined by the FIDO AppID and Facet Specification.
type TrustedFacets struct {
	Version struct {
		Major int `json:"major"`
		Minor int `json:"minor"`
	} `json:"version"`
	Ids []string `json:"ids"`
}

// TrustedFacetsEndpoint is a container of TrustedFacets.
// It is used as the response for an appId URL endpoint.
type TrustedFacetsEndpoint struct {
	TrustedFacets []TrustedFacets `json:"trustedFacets"`
}
