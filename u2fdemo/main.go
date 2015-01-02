// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.

package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/tstranex/u2f"
)

const app_id = "http://localhost:3483"

var trusted_facets = []string{app_id}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var reg_req *u2f.RegisterRequest
var reg_req_time time.Time
var registration *u2f.Registration
var sign_req *u2f.SignRequest
var sign_req_time time.Time
var counter uint32

func registerRequest(w http.ResponseWriter, r *http.Request) {
	req, err := u2f.NewRegisterRequest(app_id)
	if err != nil {
		log.Printf("u2f.NewRegisterRequest error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	log.Printf("registerRequest: %+v", req)

	reg_req = req
	reg_req_time = time.Now()
	json.NewEncoder(w).Encode(req)
}

func registerResponse(w http.ResponseWriter, r *http.Request) {
	var reg_resp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&reg_resp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("registerResponse: %+v", reg_resp)

	if reg_req == nil {
		http.Error(w, "request not found", http.StatusBadRequest)
		return
	}

	reg, err := u2f.VerifyRegisterResponse(
		reg_resp, *reg_req, reg_req_time,
		u2f.TrustedFacets{Ids: trusted_facets})
	if err != nil {
		log.Printf("VerifyRegisterResponse error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	registration = reg

	log.Printf("Registration success: %+v", registration)

	w.Write([]byte("success"))
}

func signRequest(w http.ResponseWriter, r *http.Request) {
	if registration == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	req, err := u2f.NewSignRequest(registration.KeyHandle, app_id)
	if err != nil {
		log.Printf("u2f.NewSignRequest error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	log.Printf("signRequest: %+v", req)

	sign_req = req
	sign_req_time = time.Now()
	json.NewEncoder(w).Encode(req)
}

func signResponse(w http.ResponseWriter, r *http.Request) {
	var sign_resp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&sign_resp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("signResponse: %+v", sign_resp)

	if sign_req == nil {
		http.Error(w, "request not found", http.StatusBadRequest)
		return
	}
	if registration == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	new_counter, err := u2f.VerifySignResponse(
		sign_resp, *sign_req, sign_req_time, *registration,
		u2f.TrustedFacets{Ids: trusted_facets}, counter)
	if err != nil {
		log.Printf("VerifySignResponse error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}
	counter = new_counter

	w.Write([]byte("success"))
}

const indexHtml = `
<!DOCTYPE html>
<html>
  <head>
    <script type="text/javascript" src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>
  </head>
  <body>
    <h1>FIDO U2F Go Library Demo</h1>

    <ul>
      <li><a href="https://chrome.google.com/webstore/detail/fido-u2f-universal-2nd-fa/pfboblefjcgdjicmnffhdgionmgcdmne">Install the Chrome extension</a></li>
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
          u2f.register([req], [], u2fRegistered, 100)
        });
      }

      function u2fSigned(resp) {
        $.post('/signResponse', JSON.stringify(resp)).done(function() {
          alert('Success');
        });
      }

      function sign() {
        $.getJSON('/signRequest').done(function(req) {
          u2f.sign([req], u2fSigned, 10);
        });
      }
    </script>

  </body>
</html>
`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHtml))
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/registerRequest", registerRequest)
	http.HandleFunc("/registerResponse", registerResponse)
	http.HandleFunc("/signRequest", signRequest)
	http.HandleFunc("/signResponse", signResponse)
	log.Fatal(http.ListenAndServe(":3483", nil))
}
