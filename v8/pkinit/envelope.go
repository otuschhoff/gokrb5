package pkinit

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- legacy RFC 4556 CMS TripleDES-CBC content algorithm.
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
)

const (
	aes128KeyBytes    = 16
	aes256KeyBytes    = 32
	tripleDESKeyBytes = 24
)

func oidCMSData() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1} }

func oidCMSEnvelopedData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
}

func oidRSAEncryption() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
}

func oidAES128CBC() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
}

func oidAES256CBC() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
}

func oidTripleDESCBC() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7} }

// ContentEncryptionAlgorithm is a supported PKINIT CMS content cipher.
type ContentEncryptionAlgorithm int

// Content encryption algorithms for the CMS enveloped-data reply key pack.
const (
	// AES128CBC is AES-128 in CBC mode for CMS content encryption.
	AES128CBC ContentEncryptionAlgorithm = iota
	// AES256CBC is AES-256 in CBC mode for CMS content encryption.
	AES256CBC
	TripleDESCBC
)

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsEnvelopedData struct {
	Version              int
	RecipientInfos       []cmsKeyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo cmsEncryptedContentInfo
}

type cmsKeyTransRecipientInfo struct {
	Version                int
	RecipientIdentifier    cmsIssuerAndSerialNumber
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type cmsIssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type cmsEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,tag:0"`
}

// EncryptEnvelopedData encrypts content for exactly one RSA certificate.
func EncryptEnvelopedData(
	content []byte, recipient *x509.Certificate, algorithm ContentEncryptionAlgorithm,
) ([]byte, error) {
	return encryptEnvelopedData(rand.Reader, content, recipient, algorithm)
}

func encryptEnvelopedData(
	random io.Reader,
	content []byte,
	recipient *x509.Certificate,
	algorithm ContentEncryptionAlgorithm,
) ([]byte, error) {
	publicKey, ok := recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("PKINIT CMS recipient certificate does not contain an RSA key")
	}
	block, algorithmOID, key, err := newContentCipher(random, algorithm)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, block.BlockSize())
	if _, ierr := io.ReadFull(random, iv); ierr != nil {
		return nil, fmt.Errorf("generate PKINIT CMS IV: %w", ierr)
	}
	padded := pkcs7Pad(content, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	//nolint:staticcheck // Preserve the legacy CMS RSA key transport wire format.
	encryptedKey, err := rsa.EncryptPKCS1v15(random, publicKey, key)
	if err != nil {
		return nil, fmt.Errorf("encrypt PKINIT CMS content key: %w", err)
	}
	issuer := stdRawDER(recipient.RawIssuer)
	if _, ierr := asn1.Unmarshal(recipient.RawIssuer, &issuer); ierr != nil {
		return nil, fmt.Errorf("decode recipient issuer: %w", ierr)
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT CMS content cipher IV: %w", err)
	}
	enveloped := cmsEnvelopedData{
		Version: 0,
		RecipientInfos: []cmsKeyTransRecipientInfo{{
			Version:             0,
			RecipientIdentifier: cmsIssuerAndSerialNumber{Issuer: issuer, SerialNumber: recipient.SerialNumber},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidRSAEncryption(),
				Parameters: asn1.RawValue{
					Class: asn1.ClassUniversal, Tag: asn1.TagNull, IsCompound: false, Bytes: nil, FullBytes: nil,
				},
			},
			EncryptedKey: encryptedKey,
		}},
		EncryptedContentInfo: cmsEncryptedContentInfo{
			ContentType: oidCMSData(),
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: algorithmOID, Parameters: stdRawDER(ivDER),
			},
			EncryptedContent: ciphertext,
		},
	}
	return marshalEnvelopedData(enveloped)
}

func marshalEnvelopedData(enveloped cmsEnvelopedData) ([]byte, error) {
	envelopedDER, err := asn1.Marshal(enveloped)
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT CMS EnvelopedData: %w", err)
	}
	der, err := asn1.Marshal(cmsContentInfo{
		ContentType: oidCMSEnvelopedData(),
		Content: asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: envelopedDER, FullBytes: nil,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT CMS ContentInfo: %w", err)
	}
	return der, nil
}

func stdRawDER(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: 0, Tag: 0, IsCompound: false, Bytes: nil, FullBytes: der}
}

// DecryptEnvelopedData decrypts a strict one-recipient PKINIT CMS envelope.
func DecryptEnvelopedData(der []byte, recipient *x509.Certificate, privateKey crypto.Decrypter) ([]byte, error) {
	if recipient == nil || privateKey == nil {
		return nil, errors.New("PKINIT CMS recipient certificate and private key are required")
	}
	enveloped, err := decodeEnvelopedData(der)
	if err != nil {
		return nil, err
	}
	recipientInfo := enveloped.RecipientInfos[0]
	if recipientInfo.Version != 0 || !recipientInfo.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAEncryption()) {
		return nil, errors.New("unsupported PKINIT CMS key transport algorithm")
	}
	id := recipientInfo.RecipientIdentifier
	if !bytes.Equal(id.Issuer.FullBytes, recipient.RawIssuer) || id.SerialNumber.Cmp(recipient.SerialNumber) != 0 {
		return nil, errors.New("PKINIT CMS recipient does not match certificate")
	}
	contentKey, err := privateKey.Decrypt(rand.Reader, recipientInfo.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt PKINIT CMS content key: %w", err)
	}
	return decryptCMSContent(enveloped.EncryptedContentInfo, contentKey)
}

func decodeEnvelopedData(der []byte) (*cmsEnvelopedData, error) {
	var contentInfo cmsContentInfo
	if err := strictStdUnmarshal(der, &contentInfo); err != nil {
		return nil, fmt.Errorf("decode PKINIT CMS ContentInfo: %w", err)
	}
	if !contentInfo.ContentType.Equal(oidCMSEnvelopedData()) ||
		contentInfo.Content.Class != asn1.ClassContextSpecific || contentInfo.Content.Tag != 0 {
		return nil, errors.New("PKINIT CMS content is not EnvelopedData")
	}
	var enveloped cmsEnvelopedData
	if err := strictStdUnmarshal(contentInfo.Content.Bytes, &enveloped); err != nil {
		return nil, fmt.Errorf("decode PKINIT CMS EnvelopedData: %w", err)
	}
	if enveloped.Version != 0 || len(enveloped.RecipientInfos) != 1 {
		return nil, errors.New("unsupported PKINIT CMS EnvelopedData recipient profile")
	}
	return &enveloped, nil
}

func decryptCMSContent(encryptedContent cmsEncryptedContentInfo, contentKey []byte) ([]byte, error) {
	if !encryptedContent.ContentType.Equal(oidCMSData()) {
		return nil, errors.New("unsupported PKINIT CMS encrypted content type")
	}
	block, err := contentCipher(encryptedContent.ContentEncryptionAlgorithm.Algorithm, contentKey)
	if err != nil {
		return nil, err
	}
	var iv []byte
	const invalidIV = "invalid PKINIT CMS content cipher IV"
	if err := strictStdUnmarshal(encryptedContent.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("%s: %w", invalidIV, err)
	}
	if len(iv) != block.BlockSize() {
		return nil, errors.New(invalidIV)
	}
	if len(encryptedContent.EncryptedContent) == 0 || len(encryptedContent.EncryptedContent)%block.BlockSize() != 0 {
		return nil, errors.New("invalid PKINIT CMS ciphertext length")
	}
	plaintext := make([]byte, len(encryptedContent.EncryptedContent))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, encryptedContent.EncryptedContent)
	return pkcs7Unpad(plaintext, block.BlockSize())
}

func newContentCipher(
	random io.Reader, algorithm ContentEncryptionAlgorithm,
) (cipher.Block, asn1.ObjectIdentifier, []byte, error) {
	var key []byte
	var oid asn1.ObjectIdentifier
	switch algorithm {
	case AES128CBC:
		key, oid = make([]byte, aes128KeyBytes), oidAES128CBC()
	case AES256CBC:
		key, oid = make([]byte, aes256KeyBytes), oidAES256CBC()
	case TripleDESCBC:
		key, oid = make([]byte, tripleDESKeyBytes), oidTripleDESCBC()
	default:
		return nil, nil, nil, fmt.Errorf("unsupported PKINIT CMS content encryption algorithm %d", algorithm)
	}
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, nil, nil, fmt.Errorf("generate PKINIT CMS content key: %w", err)
	}
	block, err := contentCipher(oid, key)
	return block, oid, key, err
}

func contentCipher(algorithm asn1.ObjectIdentifier, key []byte) (cipher.Block, error) {
	switch {
	case algorithm.Equal(oidAES128CBC()) && len(key) == aes128KeyBytes,
		algorithm.Equal(oidAES256CBC()) && len(key) == aes256KeyBytes:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("initialize PKINIT CMS AES cipher: %w", err)
		}
		return block, nil
	case algorithm.Equal(oidTripleDESCBC()) && len(key) == tripleDESKeyBytes:
		block, err := des.NewTripleDESCipher(key) // #nosec G405 -- used only for the legacy CMS TripleDES-CBC OID.
		if err != nil {
			return nil, fmt.Errorf("initialize PKINIT CMS TripleDES cipher: %w", err)
		}
		return block, nil
	default:
		return nil, errors.New("unsupported PKINIT CMS content encryption algorithm or key size")
	}
}

func pkcs7Pad(content []byte, blockSize int) []byte {
	padding := blockSize - len(content)%blockSize
	if padding > math.MaxUint8 {
		return nil
	}
	paddingByte := byte(padding) // #nosec G115 -- bounded by math.MaxUint8 above.
	return append(append([]byte(nil), content...), bytes.Repeat([]byte{paddingByte}, padding)...)
}

func pkcs7Unpad(content []byte, blockSize int) ([]byte, error) {
	if len(content) == 0 || len(content)%blockSize != 0 {
		return nil, errors.New("invalid PKINIT CMS content padding")
	}
	padding := int(content[len(content)-1])
	if padding == 0 || padding > blockSize || padding > len(content) {
		return nil, errors.New("invalid PKINIT CMS content padding")
	}
	var mismatch byte
	for _, value := range content[len(content)-padding:] {
		mismatch |= value ^ byte(padding) // #nosec G115 -- padding is at most block size 16 or 32 and checked above.
	}
	if mismatch != 0 {
		return nil, errors.New("invalid PKINIT CMS content padding")
	}
	return content[:len(content)-padding], nil
}

func strictStdUnmarshal(der []byte, value any) error {
	rest, err := asn1.Unmarshal(der, value)
	if err != nil {
		return fmt.Errorf("parse DER: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("CMS value contains %d trailing bytes", len(rest))
	}
	return nil
}
