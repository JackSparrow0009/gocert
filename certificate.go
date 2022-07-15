package gocert

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Certificate struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

func NewCertificate() *Certificate {
	return &Certificate{
		PublicKey:  nil,
		PrivateKey: nil,
	}
}

func NewCertificateFromFile(file string) (*Certificate, error) {
	cert := NewCertificate()

	if strings.HasSuffix(file, "pem") {
		if err := cert.LoadCertificateFromPemFile(file); err != nil {
			return nil, err
		}
	} else if strings.HasSuffix(file, "cer") {
		if err := cert.LoadCertificateFromCerFile(file); err != nil {
			return nil, err
		}
	}

	return cert, nil
}

// openssl pkcs12 -in private.pfx -nodes -out private.pem
// openssl rsa -in private.pem -out private.key
func (cert *Certificate) LoadCertificateFromPemFile(
	file string,
) error {
	pemRaw, err := ioutil.ReadFile(file)
	if err != nil {
		logrus.WithError(err).Error(file)
		return err
	}

	return cert.LoadCertificateFromPemData(pemRaw)
}

// openssl x509 -inform der -in sand.cer -out sand.pem
func (cert *Certificate) LoadCertificateFromCerFile(
	file string,
) error {
	cerRaw, err := ioutil.ReadFile(file)
	if err != nil {
		logrus.WithError(err).Error(file)
		return err
	}

	pemRaw := "-----BEGIN CERTIFICATE-----\n" + chunkSplit(
		base64.StdEncoding.EncodeToString(cerRaw), 64, "\n",
	) + "-----END CERTIFICATE-----\n"

	return cert.LoadCertificateFromPemData([]byte(pemRaw))
}

func (cert *Certificate) LoadCertificateFromPemData(
	pemRaw []byte,
) error {
	for {
		pemBlock, restBlocks := pem.Decode(pemRaw)
		if pemBlock == nil {
			break
		}

		if pemBlock.Type == "CERTIFICATE" {
			publicKey, err := LoadRsaPublicKeyFromPemBlock(
				pemBlock,
			)
			if err == nil {
				cert.PublicKey = publicKey
			}
		} else {
			privateKey, err := LoadRsaPrivateKeyFromPemBlock(
				pemBlock,
			)
			if err == nil {
				cert.PrivateKey = privateKey
			}
		}

		pemRaw = restBlocks
	}

	if cert.PrivateKey != nil {
		cert.PublicKey = &(cert.PrivateKey.PublicKey)
	}

	return nil
}

func LoadRsaPrivateKeyFromPemBlock(
	pemBlock *pem.Block,
) (*rsa.PrivateKey, error) {
	if pemBlock.Type == "PRIVATE KEY" {
		if privateKey, err := x509.ParseECPrivateKey(
			pemBlock.Bytes,
		); err == nil {
			logrus.WithField(
				"cryptoMethod", reflect.TypeOf(privateKey),
			).Error(string(pemBlock.Bytes))
			return nil, errors.New("private key type error")
		}

		privateKey10I, err := x509.ParsePKCS8PrivateKey(
			pemBlock.Bytes,
		)
		if err != nil {
			logrus.WithError(err).Error(string(pemBlock.Bytes))
			return nil, err
		}

		switch privateKey10 := privateKey10I.(type) {
		case *rsa.PrivateKey:
			return privateKey10, nil
		default:
			logrus.WithField(
				"cryptoMethod", reflect.TypeOf(privateKey10I),
			).Error(string(pemBlock.Bytes))
			return nil, errors.New("private key type error")
		}
	} else if pemBlock.Type == "RSA PRIVATE KEY" {
		privateKey09, err := x509.ParsePKCS1PrivateKey(
			pemBlock.Bytes,
		)
		if err != nil {
			logrus.WithError(err).Error(string(pemBlock.Bytes))
			return nil, err
		}

		return privateKey09, nil
	}

	return nil, errors.New("unknown error")
}

func LoadRsaPublicKeyFromPemBlock(
	pemBlock *pem.Block,
) (*rsa.PublicKey, error) {
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		logrus.WithError(err).Error(string(pemBlock.Bytes))
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"KeyUsage": certificate.KeyUsage,
	}).Debug()

	return certificate.PublicKey.(*rsa.PublicKey), nil
}

func RsaSha1Signature(
	message []byte,
	privateKey *rsa.PrivateKey,
) ([]byte, error) {
	hash := sha1.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	return rsa.SignPKCS1v15(
		rand.Reader, privateKey, crypto.SHA1, digest,
	)
}

func RsaSha1Verify(
	message []byte,
	signature []byte,
	publicKey *rsa.PublicKey,
) error {
	hash := sha1.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(
		publicKey, crypto.SHA1, digest, signature,
	)
}

func AesEncryption(
	plaintext []byte,
	key []byte,
) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.WithError(err).Error()
		return nil, err
	}

	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	plaintext, err = padder.Pad(plaintext)
	if err != nil {
		logrus.WithError(err).Error()
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func AesDecryption(
	ciphertext []byte,
	key []byte,
) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.WithError(err).Error()
		return nil, err
	}

	mode := ecb.NewECBDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	plaintext, err = padder.Unpad(plaintext)
	if err != nil {
		logrus.WithError(err).Error()
		return nil, err
	}
	return plaintext, nil
}

func RsaEncryption(
	plaintext []byte,
	publicKey *rsa.PublicKey,
) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
}

func RsaDecryption(
	ciphertext []byte,
	privateKey *rsa.PrivateKey,
) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}

func chunkSplit(body string, chunklen uint, end string) string {
	if end == "" {
		end = "\r\n"
	}

	runes, erunes := []rune(body), []rune(end)
	l := uint(len(runes))
	if l <= 1 || l < chunklen {
		return body + end
	}

	ns := make([]rune, 0, len(runes)+len(erunes))
	var i uint
	for i = 0; i < l; i += chunklen {
		if i+chunklen > l {
			ns = append(ns, runes[i:]...)
		} else {
			ns = append(ns, runes[i:i+chunklen]...)
		}
		ns = append(ns, erunes...)
	}
	return string(ns)
}
