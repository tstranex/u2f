package u2f

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestRegistrationRawConversion(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certBytes, _ := hex.DecodeString(fakeCert)
	cert, _ := x509.ParseCertificate(certBytes)

	reg := &registrationRaw{
		KeyHandle:       []byte("Fake key handle"),
		PublicKey:       privateKey.PublicKey,
		Counter:         7,
		AttestationCert: cert,
	}

	r := reg.ToRegistration()

	reg2 := &registrationRaw{}

	reg2.FromRegistration(*r)

	if !reflect.DeepEqual(reg.KeyHandle, reg2.KeyHandle) {
		t.Errorf("KeyHandle mismatch")
	}

	if !reflect.DeepEqual(reg.PublicKey, reg2.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}

	if !reg.AttestationCert.Equal(reg2.AttestationCert) {
		t.Errorf("Attestation certificate mismatch")
	}

	if reg.Counter != reg2.Counter {
		t.Errorf("Counter mismatch")
	}
}
