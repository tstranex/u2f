// U2F token implementation for integration testing

package u2f

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
    "crypto/x509"
    "encoding/json"
    "encoding/asn1"
    "encoding/binary"
    "time"
    "fmt"
    "crypto/rand"
    "math/big"
)

// Key instance attached to an AppID
type KeyInst struct {
    Generated time.Time
    AppID string
    KeyHandle string
    Private *ecdsa.PrivateKey
    Counter int
}

// Virtual U2F key
type VirtualKey struct {
    attestationKey *ecdsa.PrivateKey
    attestationCertBytes []byte
    keys []KeyInst
}


// Internal type for ASN1 coercion
type dsaSignature struct {
    R, S *big.Int
}

// Create a virtual key
func NewVirtualKey() (*VirtualKey, error) {

    // Generate attestation key
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }

    vk := VirtualKey{}
    vk.attestationKey = privateKey
    vk.attestationCertBytes = generateCert(privateKey)

    return &vk, nil
}

// Internal helper to generate certificates
func generateCert(privateKey *ecdsa.PrivateKey) []byte {
    template := x509.Certificate{}

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    template.SerialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
    
    template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign

    template.NotBefore = time.Now()
    template.NotAfter = time.Now().Add(365*24*time.Hour)

    template.SignatureAlgorithm = x509.ECDSAWithSHA256

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &(privateKey.PublicKey), privateKey)
    if err != nil {
        fmt.Println(err)
    }

    return derBytes
}

// Internal helper to find key by application ID
func (vk *VirtualKey) getKeyByAppID(appId string) *KeyInst {
    for _, v := range vk.keys {
        if v.AppID == appId {
            return &v
        }
    }

    return nil
}

// Internal helper to generate a registration signature
func (vk *VirtualKey) generateRegistrationSig(appId string, clientData []byte, keyHandle string, publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) []byte {
    
    appParam := sha256.Sum256([]byte(appId))
    challenge := sha256.Sum256(clientData)

    buf := []byte{0}
    buf = append(buf, appParam[:]...)
    buf = append(buf, challenge[:]...)
    buf = append(buf, keyHandle...)
    pk := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
    buf = append(buf, pk...)

    digest := sha256.Sum256([]byte(buf))

    r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
    if err != nil {
        fmt.Println("Error generating signature")
        fmt.Println(err)
    }

    dsaSig := dsaSignature { R: r, S: s}

    asnSig, err := asn1.Marshal(dsaSig)
    if err != nil {
        fmt.Println("Error encoding signature")
        fmt.Println(err)
    }

    return asnSig;
}

// Handle a registration request
func (vk *VirtualKey) HandleRegisterRequest(req RegisterRequest) (*RegisterResponse, error) {

    // Check if a key is already registered
    k := vk.getKeyByAppID(req.AppID)
    if k != nil {
        return nil, fmt.Errorf("Key already registered for AppID: %s", req.AppID)
    }

    // Generate key components
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    publicKey := privateKey.PublicKey

    keyHandle := "vk-" + string(len(vk.keys))

    rr := RegisterResponse{}

    // Generate client data
    cd := ClientData{
        Origin: req.AppID,
        Challenge: req.Challenge,
    }

    cdJson, _ := json.Marshal(cd);
    rr.ClientData = encodeBase64(cdJson)


    // Generate registration data
    var buf []byte
    // Magic byte
    buf = append(buf, 0x05)
    // Public Key
    buf = append(buf, elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)...)
    // Key handle
    buf = append(buf, byte(len(keyHandle)))
    buf = append(buf, []byte(keyHandle)...)
    // X509 cert
    buf = append(buf, vk.attestationCertBytes...)
    // Signature
    sig := vk.generateRegistrationSig(req.AppID, cdJson, keyHandle, &publicKey, vk.attestationKey)
    buf = append(buf, sig...)

    rr.RegistrationData = encodeBase64(buf)

    // Create local key instance
    keyInst := KeyInst{
        Generated: time.Now(),
        AppID: req.AppID,
        KeyHandle: keyHandle,
        Private: privateKey,
        Counter: 0,
    }

    vk.keys = append(vk.keys, keyInst)

    return &rr, nil
}

// Internal helper to generate an authentication signature
func (vk *VirtualKey) generateAuthenticationSig(appId string, clientData []byte, signatureData []byte, privateKey *ecdsa.PrivateKey) []byte {

    appParam := sha256.Sum256([]byte(appId))
    challenge := sha256.Sum256(clientData)

    var buf []byte
    buf = append(buf, appParam[:]...)
    buf = append(buf, signatureData...)
    buf = append(buf, challenge[:]...)

    digest := sha256.Sum256([]byte(buf))

    r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
    if err != nil {
        fmt.Println("Error generating signature")
        fmt.Println(err)
    }

    dsaSig := dsaSignature { R: r, S: s}

    asnSig, err := asn1.Marshal(dsaSig)
    if err != nil {
        fmt.Println("Error encoding signature")
        fmt.Println(err)
    }

    return asnSig;
}

// Handle an authentication request
func (vk *VirtualKey) HandleAuthenticationRequest(req SignRequest) (*SignResponse, error) {
    // Find the registered key for this service
    k := vk.getKeyByAppID(req.AppID)
    if k == nil {
        return nil, fmt.Errorf("No key registered for AppID: %s", req.AppID)
    }

    sr := SignResponse{}

    sr.KeyHandle = encodeBase64([]byte(k.KeyHandle))

    // Build client data
    cd := ClientData{
        Origin: req.AppID,
        Challenge: req.Challenge,
    }

    cdJson, _ := json.Marshal(cd);
    sr.ClientData = encodeBase64(cdJson)

    // Build signature data
    var buf []byte
    // User presence
    buf = append(buf, 0x01)
    // Use counter
    countBuf := make([]byte, 4)
    binary.LittleEndian.PutUint32(countBuf, uint32(k.Counter))
    buf = append(buf, countBuf...)

    sig := vk.generateAuthenticationSig(req.AppID, cdJson, buf, k.Private)
    buf = append(buf, sig...)
    
    sr.SignatureData = encodeBase64(buf)

    return &sr, nil
}

