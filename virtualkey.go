// U2F token implementation for integration testing

package u2f

import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
    "crypto/x509"
    "encoding/json"
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

func getPublicKey(priv interface{}) interface{} {
    switch k := priv.(type) {
    case *rsa.PrivateKey:
        return &k.PublicKey
    case *ecdsa.PrivateKey:
        return &k.PublicKey
    default:
        return nil
    }
}

func NewVirtualKey() (*VirtualKey, error) {

    // Generate attestation key
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }

    vk := VirtualKey{}
    vk.attestationKey = privateKey
    vk.attestationCertBytes = vk.GenerateCert(privateKey)

    return &vk, nil
}

func (vk *VirtualKey) GenerateCert(privateKey *ecdsa.PrivateKey) []byte {
    template := x509.Certificate{}

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    template.SerialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
    
    template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign

    template.NotBefore = time.Now()
    template.NotAfter = time.Now().Add(365*24*time.Hour)

    template.SignatureAlgorithm = x509.ECDSAWithSHA256

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, getPublicKey(privateKey), privateKey)
    if err != nil {
        fmt.Println(err)
    }

    return derBytes
}

func (vk *VirtualKey) GetKeyByAppID(appId string) *KeyInst {
    for _, v := range vk.keys {
        if v.AppID == appId {
            return &v
        }
    }

    return nil
}

func (vk *VirtualKey) GetMessageToSign(appId string, clientData []byte, keyHandle string, pubKey *ecdsa.PublicKey) []byte {
    appParam := sha256.Sum256([]byte(appId))
    challenge := sha256.Sum256(clientData)

    buf := []byte{0}
    buf = append(buf, appParam[:]...)
    buf = append(buf, challenge[:]...)
    buf = append(buf, keyHandle...)
    pk := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
    buf = append(buf, pk...)

    return buf
}

func (vk *VirtualKey) GenerateRegistrationSig(appId string, clientData []byte, keyHandle string, publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) []byte {

    buf := vk.GetMessageToSign(appId, clientData, keyHandle, publicKey)

    digest := sha256.Sum256([]byte(appId))

    r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
    if err != nil {
        fmt.Println("Error generating signature")
        fmt.Println(err)
    }

    params := privateKey.Curve.Params()
    curveOrderByteSize := params.P.BitLen() / 8
    rBytes, sBytes := r.Bytes(), s.Bytes()
    sig := make([]byte, curveOrderByteSize*2)
    copy(sig[curveOrderByteSize-len(rBytes):], rBytes)
    copy(sig[curveOrderByteSize*2-len(sBytes):], sBytes)

    cert, err := x509.ParseCertificate(vk.attestationCertBytes)
    if err != nil {
        fmt.Println("Error parsing cert")
        fmt.Println(err)
    }

    r, s = new(big.Int), new(big.Int)
    r.SetBytes(sig[:curveOrderByteSize])
    s.SetBytes(sig[curveOrderByteSize:])

    valid := ecdsa.Verify(&privateKey.PublicKey, digest[:], r, s)
    if !valid {
        fmt.Println("Error validating signature with key")
    }

    err = cert.CheckSignature(x509.ECDSAWithSHA256, buf, sig)
    if err != nil {
        fmt.Println("Error validating signature with cert")
        fmt.Println(err)
    }

    return sig;
}

func (vk *VirtualKey) HandleRegisterRequest(req RegisterRequest) (*RegisterResponse, error) {

    // Check if a key is already registered
    k := vk.GetKeyByAppID(req.AppID)
    if k != nil {
        return nil, fmt.Errorf("Key already registered for AppID: %s", req.AppID)
    }

    // Generate key components
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    publicKey := privateKey.PublicKey

    keyHandle := "testKeyHandle"

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
    sig := vk.GenerateRegistrationSig(req.AppID, cdJson, keyHandle, &publicKey, vk.attestationKey)
    buf = append(buf, sig...)

    rr.RegistrationData = encodeBase64(buf)


    return &rr, nil
}