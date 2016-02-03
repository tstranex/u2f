// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.

package main

import (
	"encoding/json"
	"log"
	"net/http"

	"fido/u2f"
)

const appID = "https://localhost:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge
var registration []byte
var counter uint32

func registerRequest(w http.ResponseWriter, r *http.Request) {
	c, err := u2f.NewChallenge(appID, trustedFacets)
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

	reg, err := u2f.Register(regResp, *challenge, nil)
	if err != nil {
		log.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}
	buf, err := reg.MarshalBinary()
	if err != nil {
		log.Printf("reg.MarshalBinary error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	registration = buf
	counter = 0

	log.Printf("Registration success: %+v", registration)
	w.Write([]byte("success"))
}

func signRequest(w http.ResponseWriter, r *http.Request) {
	if registration == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	c, err := u2f.NewChallenge(appID, trustedFacets)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c

	var reg u2f.Registration
	if err := reg.UnmarshalBinary(registration); err != nil {
		log.Printf("reg.UnmarshalBinary error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	var req u2f.AuthenticateRequest
	req.Type = "u2f_sign_request"
	req.SignRequests = append(req.SignRequests, *c.SignRequest(reg))

	log.Printf("signRequest: %+v", req)
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
	if registration == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	var reg u2f.Registration
	if err := reg.UnmarshalBinary(registration); err != nil {
		log.Printf("reg.UnmarshalBinary error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	newCounter, err := reg.Authenticate(signResp, *challenge, counter)
	if err != nil {
		log.Printf("VerifySignResponse error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}
	log.Printf("newCounter: %d", newCounter)
	counter = newCounter

	w.Write([]byte("success"))
}

const indexHTML = `
<!DOCTYPE html>
<html>
  <head>
    <script type="text/javascript" src="https://demo.yubico.com/js/u2f-api.js"></script>
  
  </head>
  <body>
    <h1>FIDO U2F Go Library Demo</h1>

    <ul>
      <li><a href="javascript:register();">Register token</a></li>
      <li><a href="javascript:sign();">Authenticate</a></li>
    </ul>

    <script src="//code.jquery.com/jquery-1.11.2.min.js"></script>
    <script>
	function u2fRegistered(resp) {
		$.post('/registerResponse', JSON.stringify(resp)).done(function() {
		 	alert('Success');
		});
	}

	function register() {
        $.getJSON('/registerRequest').done(function(req) {
          	u2f.register([req], [], u2fRegistered, 1000);
        });
      }

	function u2fSigned(resp) {
        $.post('/signResponse', JSON.stringify(resp)).done(function() {
			alert('Success');
        });
	}

	function sign() {
		$.getJSON('/signRequest').done(function(req) {
			console.log('sign req -',req.signRequests)
			u2f.sign(req.signRequests, u2fSigned, 10);
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

	log.Printf("Running on %s", appID)
	log.Fatal(http.ListenAndServeTLS(":3483", "server.crt", "server.key", nil))
}
