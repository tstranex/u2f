// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.

package u2f

type JwkKey struct {
	KTy string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type ClientData struct {
	Typ       string `json:"typ"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	CIDPubKey string `json:"cid_pubkey"`
}

type RegisterRequest struct {
	Version   string `json:"version"`
	Challenge string `json:"challenge"`
	AppId     string `json:"appId"`
}

type RegisterResponse struct {
	RegistrationData string `json:"registrationData"`
	ClientData       string `json:"clientData"`
}

type SignRequest struct {
	Version   string `json:"version"`
	Challenge string `json:"challenge"`
	KeyHandle string `json:"keyHandle"`
	AppId     string `json:"appId"`
}

type SignResponse struct {
	KeyHandle     string `json:"keyHandle"`
	SignatureData string `json:"signatureData"`
	ClientData    string `json:"clientData"`
}

type TrustedFacets struct {
	Version struct {
		Major int `json:"major"`
		Minor int `json:"minor"`
	} `json:"version"`
	Ids []string `json:"ids"`
}

type TrustedFacetsEndpoint struct {
	TrustedFacets []TrustedFacets `json:"trustedFacets"`
}
