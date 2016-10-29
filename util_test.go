// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
	"testing"
	"encoding/hex"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/rand"
	"reflect"
)

func TestVerifyClientDataWithoutChannelId(t *testing.T) {
	const clientData = "{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"KLWuflMwjv5UfJ9Ua1Kaaw\",\"origin\":\"http://localhost:3483\",\"cid_pubkey\":\"\"}"

	cbytes, _ := decodeBase64("KLWuflMwjv5UfJ9Ua1Kaaw")
	c := Challenge{
		Challenge:     cbytes,
		TrustedFacets: []string{"http://localhost:3483"},
	}

	err := verifyClientData([]byte(clientData), c)
	if err != nil {
		t.Error(err)
	}
}

func TestVerifyClientDataWithChannelId(t *testing.T) {
	const clientData = "{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"

	cbytes, _ := decodeBase64("vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo")
	c := Challenge{
		Challenge:     cbytes,
		TrustedFacets: []string{"http://example.com"},
	}

	err := verifyClientData([]byte(clientData), c)
	if err != nil {
		t.Error(err)
	}
}

const fakeCert = "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df"
	
type fidoToken struct {
	KeyHandle string
	PublicKey string
	Certificate string
	Counter uint
}

func TestMarshalUnmarshalRegistration(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certBytes, _ := hex.DecodeString(fakeCert)
	cert, _ := x509.ParseCertificate(certBytes)

	reg := &Registration{
		KeyHandle: []byte("Fake key handle"),
		PubKey: privateKey.PublicKey,
		Counter: 7,
		AttestationCert: cert,
	}

	ft := fidoToken{}

	reg.MarshalStruct(&ft)

	reg2 := &Registration{}

	reg2.UnmarshalStruct(&ft)

	if !reflect.DeepEqual(reg.KeyHandle, reg2.KeyHandle) {
		t.Errorf("KeyHandle mismatch")
	}

	if !reflect.DeepEqual(reg.PubKey, reg2.PubKey) {
		t.Errorf("PublicKey mismatch")
	}

	if !reg.AttestationCert.Equal(reg2.AttestationCert) {
		t.Errorf("Attestation certificate mismatch")
	}

	if reg.Counter != reg2.Counter {
		t.Errorf("Counter mismatch")
	}
}

