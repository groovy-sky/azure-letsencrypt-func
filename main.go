package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "fmt"
    "log"
    "os"

    "github.com/go-acme/lego/certcrypto"
    "github.com/go-acme/lego/certificate"
    "github.com/go-acme/lego/lego"
    "github.com/go-acme/lego/providers/dns/azure"
    "github.com/go-acme/lego/registration"
)

type CertUser struct {
    Email        string
    Registration *registration.Resource
    key          crypto.PrivateKey
}

func (u *CertUser) GetEmail() string {
    return u.Email
}

func (u CertUser) GetRegistration() *registration.Resource {
    return u.Registration
}

func (u *CertUser) GetPrivateKey() crypto.PrivateKey {
    return u.key
}

func main() {

    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    certUser := CertUser{
        Email: os.Getenv("CERT_USER_EMAIL"),
        key:   privateKey,
    }

    config := lego.NewConfig(&certUser)

    config.Certificate.KeyType = certcrypto.RSA2048

    client, err := lego.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }

    provider, err := azure.NewDNSProvider()
    if err != nil {
        log.Fatal(err)
    }

    err = client.Challenge.SetDNS01Provider(provider)
    if err != nil {
        log.Fatal(err)
    }

    reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
    if err != nil {
        log.Fatal(err)
    }
    certUser.Registration = reg

    request := certificate.ObtainRequest{
        Domains: []string{os.Getenv("CERT_DOMAIN")},
        Bundle:  true,
    }
    certificates, err := client.Certificate.Obtain(request)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("%#v\n", certificates)
}
