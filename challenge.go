package u2f

import (
	"crypto/rand"
	"time"
)

// Challenge represents a single transaction between the server and
// authenticator. This data will typically be stored in a database.
type Challenge struct {
	Challenge      []byte
	Timestamp      time.Time
	AppID          string
	TrustedFacets  []string
	RegisteredKeys []Registration
}

// NewChallenge generates a challenge for the given application, trusted facets, and registered keys
// This challenge can then be used to generate and validate registration or authorization requests
func NewChallenge(appID string, trustedFacets []string, registeredKeys []Registration) (*Challenge, error) {
	challenge := make([]byte, 32)
	n, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, ErrRandomGen
	}

	var c Challenge
	c.Challenge = challenge
	c.Timestamp = time.Now()
	c.AppID = appID
	c.TrustedFacets = trustedFacets
	c.RegisteredKeys = registeredKeys

	return &c, nil
}
