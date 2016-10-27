// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
    "testing"
    "fmt"
)

func TestVirtualKey(t *testing.T) {
    
    vk, err := NewVirtualKey()
    if err != nil {
        t.Error(err)
        t.FailNow()
    }

    app_id := "http://localhost"

    // Generate registration request
    var keyHandles []string
    c1, _ := NewChallenge(app_id, []string{app_id})
    registerReq := c1.RegisterRequest(keyHandles)

    // Pass to virtual token
    resp, err := vk.HandleRegisterRequest(*registerReq)
    if err != nil {
        t.Error(err)
        t.FailNow()
    }

    // Register virtual token
    // Attestation cert is self signed, so skip checking that
    reg, err := Register(*resp, *c1, &Config{SkipAttestationVerify: true})
    if err != nil {
        t.Error(err)
        t.FailNow()
    }

    // Send authentication request to the browser / token.
    var registrations []Registration
    registrations = append(registrations, *reg)
    c2, _ := NewChallenge(app_id, []string{app_id})
    signReq := c2.SignRequest(registrations)

    // Pass to virtual token
    signResp, err := vk.HandleAuthenticationRequest(*signReq)
    if err != nil {
        t.Error(err)
        t.FailNow()
    }

    // Read response from the browser / token.
    newCounter, err := signReq.Authenticate(*signResp, 0)
    if err != nil {
        t.Error(err)
        t.FailNow()
    }

    fmt.Printf("Counter: %+v\n", newCounter)

}
