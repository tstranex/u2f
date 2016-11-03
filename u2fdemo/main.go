// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"

	"github.com/ryankurte/go-u2f"
)

const appID = "https://localhost:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge

var registrations []u2f.Registration
var counter uint32

func registerRequest(w http.ResponseWriter, r *http.Request) {
	c, err := u2f.NewChallenge(appID, trustedFacets, registrations)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c
	req := c.RegisterRequest()

	log.Printf("registerRequest: %+v", req)
	json.NewEncoder(w).Encode(req)
}

func registerResponse(w http.ResponseWriter, r *http.Request) {
	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	if challenge == nil {
		http.Error(w, "challenge not found", http.StatusBadRequest)
		return
	}

	reg, err := challenge.Register(regResp, &u2f.RegistrationConfig{SkipAttestationVerify: true})
	if err != nil {
		log.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	registrations = append(registrations, *reg)
	counter = 0

	log.Printf("Registration success: %+v", reg)
	w.Write([]byte("success"))
}

func signRequest(w http.ResponseWriter, r *http.Request) {
	if registrations == nil {
		http.Error(w, "registrations missing", http.StatusBadRequest)
		return
	}

	c, err := u2f.NewChallenge(appID, trustedFacets, registrations)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c

	req := c.SignRequest()

	log.Printf("authenticateRequest: %+v", req)
	json.NewEncoder(w).Encode(req)
}

func signResponse(w http.ResponseWriter, r *http.Request) {
	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("signResponse: %+v", signResp)

	if challenge == nil {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}
	if registrations == nil {
		http.Error(w, "registrations missing", http.StatusBadRequest)
		return
	}

	newCounter, err := challenge.Authenticate(signResp)
	if err == nil {
		log.Printf("newCounter: %d", newCounter)
		w.Write([]byte("success"))
		return
	}

	log.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}

const indexHTML = `
<!DOCTYPE html>
<html>
  <head>
    <script src="//code.jquery.com/jquery-1.11.2.min.js"></script>
    <script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script>

  </head>
  <body>
    <h1>FIDO U2F Go Library Demo</h1>

    <ul>
      <li><a href="javascript:register();">Register token</a></li>
      <li><a href="javascript:sign();">Authenticate</a></li>
    </ul>

    <script>

  function u2fRegistered(resp) {
    console.log(resp);
    $.post('/registerResponse', JSON.stringify(resp)).done(function() {
      alert('Success');
    });
  }

  function register() {
    $.getJSON('/registerRequest').done(function(req) {
      console.log("Registration request:")
      console.log(req);
      u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 60);
    });
  }

  function u2fSigned(resp) {
    console.log(resp);
    console.log("Sign response:")

    $.post('/signResponse', JSON.stringify(resp)).done(function() {
        alert('Success');
    });
  }

  function sign() {
    $.getJSON('/signRequest').done(function(req) {
      console.log("Sign request:")
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 60);
    });
  }

    </script>

  </body>
</html>
`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHTML))
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/registerRequest", registerRequest)
	http.HandleFunc("/registerResponse", registerResponse)
	http.HandleFunc("/signRequest", signRequest)
	http.HandleFunc("/signResponse", signResponse)

	certs, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Running on %s", appID)

	var s http.Server
	s.Addr = ":3483"
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certs}}
	log.Fatal(s.ListenAndServeTLS("", ""))
}
