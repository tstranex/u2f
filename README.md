# Go FIDO U2F Library

This Go package implements the parts of the FIDO U2F specification required on
the server side of an application.

## Features

- Native Go implementation
- No dependancies other than the Go standard library
- Token attestation certificate verification

## Usage

Please visit http://godoc.org/github.com/tstranex/u2f for the full
documentation.

### How to enrol a new token

```
app_id := "http://localhost"
c, _ := NewChallenge(app_id, []string{app_id})
req, _ := c.RegisterRequest()
// Send the request to the browser.
var resp RegisterResponse
// Read resp from the browser.
reg, err := Register(resp, c)
if err != nil {
    // Registration failed.
}
// Store reg in the database.
```

### How to perform an authentication

```
var reg Registration
// Fetch reg from the database.
c, _ := NewChallenge(app_id, []string{app_id})
req, _ := c.SignRequest(reg)
// Send the request to the browser.
var resp SignResponse
// Read resp from the browser.
new_counter, err := reg.Authenticate(resp, c)
if err != nil {
    // Authentication failed.
}
reg.Counter = new_counter
// Store updated Registration in the database.
```

## Installation

```
$ go get github.com/tstranex/u2f
```

## Example

See u2fdemo/main.go for an full example server. To run it:

```
$ go install github.com/tstranex/u2f/u2fdemo
$ ./bin/u2fdemo
```

Open http://localhost:3483 in Chrome and install the
[Chrome extension](https://chrome.google.com/webstore/detail/fido-u2f-universal-2nd-fa/pfboblefjcgdjicmnffhdgionmgcdmne).
You can then test registering and authenticating using your token.

## License

The Go FIDO U2F Library is licensed under the MIT License.
