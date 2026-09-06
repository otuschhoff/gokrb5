package pkinit

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	goforkasn1 "github.com/jcmturner/gofork/encoding/asn1"
)

// VerifiedSignedData is CMS content whose signature and signed attributes
// have been cryptographically verified. Certificate trust is evaluated later.
type VerifiedSignedData struct {
	Content      []byte
	Signer       *x509.Certificate
	Certificates []*x509.Certificate
}

// SignSignedData creates a DER CMS SignedData value for a PKINIT content type.
func SignSignedData(contentType goforkasn1.ObjectIdentifier, content []byte, chain []*x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if len(chain) == 0 || signer == nil {
		return nil, fmt.Errorf("PKINIT CMS signer and certificate chain are required")
	}
	eci, err := protocol.NewEncapsulatedContentInfo(asn1.ObjectIdentifier(contentType), content)
	if err != nil {
		return nil, fmt.Errorf("create PKINIT CMS content: %w", err)
	}
	signedData, err := protocol.NewSignedData(eci)
	if err != nil {
		return nil, fmt.Errorf("create PKINIT CMS SignedData: %w", err)
	}
	if err := signedData.AddSignerInfo(chain, signer); err != nil {
		return nil, fmt.Errorf("sign PKINIT CMS content: %w", err)
	}
	der, err := signedData.ContentInfoDER()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT CMS SignedData: %w", err)
	}
	return der, nil
}

// VerifySignedData verifies a DER CMS SignedData value and its PKINIT content type.
func VerifySignedData(der []byte, expectedContentType goforkasn1.ObjectIdentifier) (*VerifiedSignedData, error) {
	var contentInfo protocol.ContentInfo
	rest, err := asn1.Unmarshal(der, &contentInfo)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("decode PKINIT CMS ContentInfo: %w", cmsDecodeError(err, len(rest)))
	}
	canonical, err := asn1.Marshal(contentInfo)
	if err != nil || !bytes.Equal(canonical, der) {
		return nil, fmt.Errorf("PKINIT CMS ContentInfo is not DER encoded")
	}
	if !contentInfo.ContentType.Equal(oid.ContentTypeSignedData) {
		return nil, fmt.Errorf("PKINIT CMS content type %v is not SignedData", contentInfo.ContentType)
	}
	signedData, err := contentInfo.SignedDataContent()
	if err != nil {
		return nil, fmt.Errorf("decode PKINIT CMS SignedData: %w", err)
	}
	if !signedData.EncapContentInfo.EContentType.Equal(asn1.ObjectIdentifier(expectedContentType)) {
		return nil, fmt.Errorf("unexpected PKINIT CMS eContentType %v", signedData.EncapContentInfo.EContentType)
	}
	if len(signedData.SignerInfos) != 1 {
		return nil, fmt.Errorf("PKINIT CMS SignedData has %d signers, want 1", len(signedData.SignerInfos))
	}
	if len(signedData.DigestAlgorithms) != 1 {
		return nil, fmt.Errorf("PKINIT CMS SignedData has %d digest algorithms, want 1", len(signedData.DigestAlgorithms))
	}
	content, err := signedData.EncapContentInfo.EContentValue()
	if err != nil || content == nil {
		return nil, fmt.Errorf("decode PKINIT CMS eContent: %w", cmsDecodeError(err, 0))
	}
	certificates, err := signedData.X509Certificates()
	if err != nil {
		return nil, fmt.Errorf("decode PKINIT CMS certificates: %w", err)
	}
	signerInfo := signedData.SignerInfos[0]
	signer, err := signerInfo.FindCertificate(certificates)
	if err != nil {
		return nil, fmt.Errorf("find PKINIT CMS signer certificate: %w", err)
	}
	attributeType, err := signerInfo.GetContentTypeAttribute()
	if err != nil || !attributeType.Equal(signedData.EncapContentInfo.EContentType) {
		return nil, fmt.Errorf("verify PKINIT CMS content-type attribute: %w", cmsAttributeError(err))
	}
	hashFunc, err := signerInfo.Hash()
	if err != nil || !hashFunc.Available() {
		return nil, fmt.Errorf("unsupported PKINIT CMS digest algorithm")
	}
	if !signedData.DigestAlgorithms[0].Algorithm.Equal(signerInfo.DigestAlgorithm.Algorithm) {
		return nil, fmt.Errorf("PKINIT CMS digest algorithm set does not match signer")
	}
	digest := hashFunc.New()
	digest.Write(content)
	declaredDigest, err := signerInfo.GetMessageDigestAttribute()
	if err != nil || subtle.ConstantTimeCompare(digest.Sum(nil), declaredDigest) != 1 {
		return nil, fmt.Errorf("verify PKINIT CMS message-digest attribute: %w", cmsAttributeError(err))
	}
	signatureAlgorithm := signerInfo.X509SignatureAlgorithm()
	if signatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("unsupported PKINIT CMS signature algorithm")
	}
	signedAttributes, err := signerInfo.SignedAttrs.MarshaledForVerification()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT CMS signed attributes: %w", err)
	}
	if err := signer.CheckSignature(signatureAlgorithm, signedAttributes, signerInfo.Signature); err != nil {
		return nil, fmt.Errorf("verify PKINIT CMS signature: %w", err)
	}
	return &VerifiedSignedData{Content: content, Signer: signer, Certificates: certificates}, nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert != nil && bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func cmsDecodeError(err error, trailing int) error {
	if err != nil {
		return err
	}
	if trailing != 0 {
		return fmt.Errorf("%d trailing bytes", trailing)
	}
	return fmt.Errorf("content is absent")
}

func cmsAttributeError(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("attribute value does not match content")
}
