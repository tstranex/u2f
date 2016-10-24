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
    c, _ := NewChallenge(app_id, []string{app_id})
    //fmt.Printf("Challenge: %+v\n", c)
    req := c.RegisterRequest()

    // Pass to virtual token
    resp, err := vk.HandleRegisterRequest(*req)
    if err != nil {
        t.Error(err)
        t.FailNow()
    }

    // Register virtual token
    reg, err := Register(*resp, *c, &Config{SkipAttestationVerify: true})
    if err != nil {
        t.Error(err)
        t.FailNow()
    }

    fmt.Println("Registration: %+v\n", reg)

}
