# Go FIDO U2F Library

A server side implementation of the FIDO U2F specification in GO, based on [tstranex/u2f](https://github.com/tstranex/u2f).  

This fork alters the API to simply handle multiple tokens, and to correspond better to the U2F JavaScript specification.  

This also includes a virtual token implementation for integration testing, see [virtualkey_test.go](virtualkey_test.go) for an example.  

## Features

- Native Go implementation
- No dependencies other than the Go standard library
- Token attestation certificate verification

## Status

[![Build Status](https://travis-ci.org/ryankurte/go-u2f.svg?branch=master)](https://travis-ci.org/ryankurte/go-u2f)

Components working, API subject to change as better interfaces are realised. Suggest installation with `gopkg.in/ryankurte/go-u2f.v1`.

## Usage

Please visit http://godoc.org/github.com/ryankurte/go-u2f for the full
documentation.

### Import
```go
import u2f "github.com/ryankurte/go-u2f"
```

### Request Enrolment

```go
// Fetch registration entries from the database
var registeredKeys []u2f.Registration

app_id := "http://localhost"

// Generate registration request
c1, _ := u2f.NewChallenge(app_id, []string{app_id}, registeredKeys)
req, _ := c1.RegisterRequest()

// Send request to browser
...

// Save challenge to session
...
```

### Check Enrolment
```go
// Read challenge from session
var c1 u2f.Challenge

// Read response from the browser
var resp u2f.RegisterResponse

// Perform registration
reg, err := c1.Register(resp)
if err != nil {
    // Registration failed.
}

// Store registration in the database against a user
...
```

### Request Authentication

```go
// Fetch registration entries for a user from the database
var registeredKeys []Registration

app_id := "http://localhost"

// Generate authentication request
c2, _ := u2f.NewChallenge(app_id, []string{app_id}, registeredKeys)
req, _ := c2.SignRequest()

// Send request to browser
...

// Save challenge to session
...
```

### Check Authentication
```go
// Read challenge from session
var c1 u2f.Challenge

// Read response from the browser
var resp SignResponse

// Perform authentication
reg, err := c2.Authenticate(resp)
if err != nil {
    // Authentication failed.
}

// Store updated registration (usage count) in the database
...

```

### Client side usage
```js
u2f.register(req.appId, req.registerRequests, req.registeredKeys, registerCallback, timeout);
u2f.sign(req.appId, req.challenge, req.registeredKeys, signCallback, timeout);
```
See [u2fdemo/main.go](u2fdemo/main.go) for an example.

## Installation

```
$ go get github.com/ryankurte/u2f
```

## Example

See u2fdemo/main.go for an full example server. To run it:

```
$ go install github.com/ryankurte/u2f/u2fdemo
$ ./bin/u2fdemo
```

Or with from the repository:
```
$ go run u2fdemo/*
```


Open https://localhost:3483 in Chrome.
Ignore the SSL warning (due to the self-signed certificate for localhost).
You can then test registering and authenticating using your token.

## License

The Go FIDO U2F Library is licensed under the MIT License.
