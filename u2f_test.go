// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.

package u2f

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFull(t *testing.T) {
	// These are actual responses from a Yubikey with Chrome.

	const app_id = "http://localhost:3483"

	reg_req := RegisterRequest{
		Version:   "U2F_V2",
		Challenge: "s4UJ3wkN80p4wLjyI2Guv-_a-s7LV54Ic9PAZvHo_lM",
		AppId:     app_id,
	}

	const reg_resp_json = "{\"registrationData\":\"BQTD17IP7bZ3Gcd7l5Ao4qqohsUcm0bcXgHLpn0pv2VWNl7SBtNFo0wEoAdMrHlFXGzJgQz_bRZaKXZfHyd3fAo0QJmZkSv9ZbTKz7TVO6jnOcKGrSHb15JDatMMFxHxN5BR56CE3sj10jtGOY7szQIi4RGU6kONIuriAarxuEFJ5IswggIcMIIBBqADAgECAgQk26tAMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKzEpMCcGA1UEAwwgWXViaWNvIFUyRiBFRSBTZXJpYWwgMTM1MDMyNzc4ODgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCsJS-NH1HeUHEd46-xcpN7SpHn6oeb-w5r-veDCBwy1vUvWnJanjjv4dR_rV5G436ysKUAXUcsVe5fAnkORo2oxIwEDAOBgorBgEEAYLECgEBBAAwCwYJKoZIhvcNAQELA4IBAQCjY64OmDrzC7rxLIst81pZvxy7ShsPy2jEhFWEkPaHNFhluNsCacNG5VOITCxWB68OonuQrIzx70MfcqwYnbIcgkkUvxeIpVEaM9B7TI40ZHzp9h4VFqmps26QCkAgYfaapG4SxTK5k_lCPvqqTPmjtlS03d7ykkpUj9WZlVEN1Pf02aTVIZOHPHHJuH6GhT6eLadejwxtKDBTdNTv3V4UlvjDOQYQe9aL1jUNqtLDeBHso8pDvJMLc0CX3vadaI2UVQxM-xip4kuGouXYj0mYmaCbzluBDFNsrzkNyL3elg3zMMrKvAUhoYMjlX_-vKWcqQsgsQ0JtSMcWMJ-umeDMEQCIApTYovLr8citOpIKkyNidCQz7UeSOWNMlPBB-s3r4G9AiAskXkh7iale4QDe6a-675L3xzohYb8Fcvz3gH6dkDLvw\",\"version\":\"U2F_V2\",\"challenge\":\"s4UJ3wkN80p4wLjyI2Guv-_a-s7LV54Ic9PAZvHo_lM\",\"appId\":\"http://localhost:3483\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6InM0VUozd2tOODBwNHdManlJMkd1di1fYS1zN0xWNTRJYzlQQVp2SG9fbE0iLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjM0ODMiLCJjaWRfcHVia2V5IjoiIn0\"}"
	var reg_resp RegisterResponse
	if err := json.Unmarshal([]byte(reg_resp_json), &reg_resp); err != nil {
		t.Error(err)
	}

	var trusted_facets TrustedFacets
	trusted_facets.Ids = []string{app_id}
	reg_req_time := time.Now().Add(-time.Minute)
	reg, err := VerifyRegisterResponse(reg_resp, reg_req, reg_req_time, trusted_facets)
	if err != nil {
		t.Error(err)
	}

	sign_req := SignRequest{
		AppId:     app_id,
		Challenge: "PzN6SGiUaeypErE3SCHeRlkRxVwfWlGVi35gfq6LsdY",
		KeyHandle: "mZmRK_1ltMrPtNU7qOc5woatIdvXkkNq0wwXEfE3kFHnoITeyPXSO0Y5juzNAiLhEZTqQ40i6uIBqvG4QUnkiw",
		Version:   "U2F_V2",
	}

	const sign_resp_json = "{\"keyHandle\":\"mZmRK_1ltMrPtNU7qOc5woatIdvXkkNq0wwXEfE3kFHnoITeyPXSO0Y5juzNAiLhEZTqQ40i6uIBqvG4QUnkiw\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiUHpONlNHaVVhZXlwRXJFM1NDSGVSbGtSeFZ3ZldsR1ZpMzVnZnE2THNkWSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzQ4MyIsImNpZF9wdWJrZXkiOiIifQ\",\"signatureData\":\"AQAAAAYwRAIgBuyafOXoc9Q7fARcs2JbCZdtnMzVCyeJC-J-2Im1IBsCIDxkzmvPX9RCY8uts4wM1y4wEX9LmNH2Mz_VFd-JdyGE\"}"
	var sign_resp SignResponse
	if err := json.Unmarshal([]byte(sign_resp_json), &sign_resp); err != nil {
		t.Error(err)
	}

	sign_req_time := time.Now().Add(-time.Minute)
	new_counter, err := VerifySignResponse(
		sign_resp, sign_req, sign_req_time, *reg, trusted_facets, 0)
	if err != nil {
		t.Error(err)
	}
	if new_counter != 6 {
		t.Errorf("Wrong new counter: %d", new_counter)
	}
}
