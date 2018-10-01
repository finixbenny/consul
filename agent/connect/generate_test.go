package connect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSerialNumber(t *testing.T) {
	n1, err := GenerateSerialNumber()
	require.Nil(t, err)

	n2, err := GenerateSerialNumber()
	require.Nil(t, err)
	require.NotEqual(t, n1, n2)

	n3, err := GenerateSerialNumber()
	require.Nil(t, err)
	require.NotEqual(t, n1, n3)
	require.NotEqual(t, n2, n3)
}

func TestGeneratePrivateKey(t *testing.T) {
	t.Parallel()
	_, p, err := GeneratePrivateKey()
	require.Nil(t, err)
	require.NotEmpty(t, p)
	require.Contains(t, p, "BEGIN EC PRIVATE KEY")
	require.Contains(t, p, "END EC PRIVATE KEY")

	block, _ := pem.Decode([]byte(p))
	pk, err := x509.ParseECPrivateKey(block.Bytes)

	require.Nil(t, err)
	require.NotNil(t, pk)
	require.Equal(t, 256, pk.Params().BitSize)
}

type TestSigner struct {
	public interface{}
}

func (s *TestSigner) Public() crypto.PublicKey {
	return s.public
}

func (s *TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte{}, nil
}

func TestGenerateCA(t *testing.T) {
	t.Parallel()
	sn, err := GenerateSerialNumber()
	require.Nil(t, err)
	var s crypto.Signer

	// test what happens without key
	s = &TestSigner{}
	ca, err := GenerateCA(s, sn, nil)
	require.Error(t, err)
	require.Empty(t, ca)

	// test what happens with wrong key
	s = &TestSigner{public: &rsa.PublicKey{}}
	ca, err = GenerateCA(s, sn, nil)
	require.Error(t, err)
	require.Empty(t, ca)

	// test what happens with correct key
	s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	ca, err = GenerateCA(s, sn, nil)
	require.Nil(t, err)
	require.NotEmpty(t, ca)

	cert, err := ParseCert(ca)
	require.Nil(t, err)
	require.Equal(t, fmt.Sprintf("Consul CA %d", sn), cert.Subject.CommonName)
	require.Equal(t, true, cert.IsCA)
}

func TestGenerateCert(t *testing.T) {
	t.Parallel()
	sn, err := GenerateSerialNumber()
	require.Nil(t, err)
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	ca, err := GenerateCA(signer, sn, nil)
	require.Nil(t, err)

	sn, err = GenerateSerialNumber()
	require.Nil(t, err)
	name := "Consul Cert"
	certificate, pk, err := GenerateCert(signer, ca, sn, name)
	require.Nil(t, err)
	require.NotEmpty(t, certificate)
	require.NotEmpty(t, pk)

	cert, err := ParseCert(certificate)
	require.Nil(t, err)
	require.Equal(t, cert.Subject.CommonName, name)
	signee, err := ParseSigner(pk)
	require.Nil(t, err)
	certID, err := KeyId(signee.Public())
	require.Nil(t, err)
	require.Equal(t, certID, cert.SubjectKeyId)
	caID, err := KeyId(signer.Public())
	require.Nil(t, err)
	require.Equal(t, caID, cert.AuthorityKeyId)
	require.Contains(t, cert.Issuer.CommonName, "Consul CA")
	require.Equal(t, false, cert.IsCA)

	// format so that we don't take anything smaller than second into account.
	require.Equal(t, cert.NotBefore.Format(time.ANSIC), time.Now().UTC().Format(time.ANSIC))
	require.Equal(t, cert.NotAfter.Format(time.ANSIC), time.Now().Add(time.Minute*60*24*365).UTC().Format(time.ANSIC))
}
