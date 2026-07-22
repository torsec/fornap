package utils_attester

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"

	sabi "github.com/google/go-sev-guest/abi"
	sg "github.com/google/go-sev-guest/client"
	tg "github.com/google/go-tdx-guest/client"
	tabi "github.com/google/go-tdx-guest/client/linuxabi"
	tpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tpm-tools/client"
	pba "github.com/google/go-tpm-tools/proto/attest"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	maxIssuingCertificateURLs = 3
	maxCertChainLength        = 4
)

type Session interface {
	io.Closer
	Auth() (tpm2.AuthCommand, error)
}

func Attest(opts client.AttestOpts, rw io.ReadWriter, k *client.Key) (*pba.Attestation, error) {
	if len(opts.Nonce) == 0 {
		return nil, fmt.Errorf("provided nonce must not be empty")
	}
	sels, err := allocatedPCRs(rw)
	if err != nil {
		return nil, err
	}

	attestation := pba.Attestation{}
	if attestation.AkPub, err = k.PublicArea().Encode(); err != nil {
		return nil, fmt.Errorf("failed to encode public area: %w", err)
	}
	attestation.AkCert = k.CertDERBytes()
	for _, sel := range sels {
		quote, err := Quote(rw, k, sel, opts.Nonce)
		if err != nil {
			return nil, err
		}
		attestation.Quotes = append(attestation.Quotes, quote)
	}
	if opts.TCGEventLog == nil {
		if attestation.EventLog, err = GetEventLog(rw); err != nil {
			return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
		}
	} else {
		attestation.EventLog = opts.TCGEventLog
	}
	if len(opts.CanonicalEventLog) != 0 {
		attestation.CanonicalEventLog = opts.CanonicalEventLog
	}

	// Attempt to construct certificate chain. fetchIssuingCertificate checks if
	// AK cert is present and contains intermediate cert URLs.
	if opts.CertChainFetcher != nil {
		attestation.IntermediateCerts, err = getCertificateChain(k, opts.CertChainFetcher)
		if err != nil {
			return nil, fmt.Errorf("fetching certificate chain: %w", err)
		}
	}

	if err := getTEEAttestationReport(&attestation, opts); err != nil {
		return nil, fmt.Errorf("collecting TEE attestation report: %w", err)
	}

	return &attestation, nil
}

func getTEEAttestationReport(attestation *pba.Attestation, opts client.AttestOpts) error {
	device := opts.TEEDevice
	if device != nil {
		return device.AddAttestation(attestation, opts)
	}

	// TEEDevice can't be nil while TEENonce is non-nil
	if opts.TEENonce != nil {
		return fmt.Errorf("got non-nil TEENonce when TEEDevice is nil: %v", opts.TEENonce)
	}

	// Try SEV-SNP.
	if device, err := CreateSevSnpDevice(); err == nil {
		// Don't return errors if the attestation collection fails, since
		// the user didn't specify a TEEDevice.
		device.AddAttestation(attestation, opts)
		device.Close()
		return nil
	}

	// Try TDX.
	if quoteProvider, err := CreateTdxQuoteProvider(); err == nil {
		// Don't return errors if the attestation collection fails, since
		// the user didn't specify a TEEDevice.
		quoteProvider.AddAttestation(attestation, opts)
		quoteProvider.Close()
		return nil
	}
	// Add more devices here.
	return nil
}

type TdxDevice struct {
	Device tg.Device
}

// TdxQuoteProvider encapsulates the TDX attestation device to add its attestation quote
// to a pb.Attestation.
type TdxQuoteProvider struct {
	QuoteProvider tg.QuoteProvider
}

func CreateTdxQuoteProvider() (*TdxQuoteProvider, error) {
	qp, err := tg.GetQuoteProvider()
	if err != nil {
		return nil, err
	}
	if qp.IsSupported() != nil {
		// TDX quote provider has a fallback mechanism to fetch attestation quote
		// via device driver in case ConfigFS is not supported, so checking for TDX
		// device availability here. Once Device interface is fully removed from
		// subsequent go-tdx-guest versions, then below OpenDevice call should be
		// removed as well.
		d, err2 := tg.OpenDevice()
		if err2 != nil {
			return nil, fmt.Errorf("neither TDX device, nor quote provider is supported")
		}
		d.Close()
	}

	return &TdxQuoteProvider{QuoteProvider: qp}, nil
}

func (qp *TdxQuoteProvider) AddAttestation(attestation *pba.Attestation, opts client.AttestOpts) error {
	var tdxNonce [tabi.TdReportDataSize]byte
	err := fillTdxNonce(opts, tdxNonce[:])
	if err != nil {
		return err
	}
	quote, err := tg.GetQuote(qp.QuoteProvider, tdxNonce)
	if err != nil {
		return err
	}
	return setTeeAttestationTdxQuote(quote, attestation)
}

func fillTdxNonce(opts client.AttestOpts, tdxNonce []byte) error {
	if len(opts.TEENonce) == 0 {
		copy(tdxNonce[:], opts.Nonce)
	} else if len(opts.TEENonce) != tabi.TdReportDataSize {
		return fmt.Errorf("the TEENonce size is %d. Intel TDX device requires %d", len(opts.TEENonce), tabi.TdReportDataSize)
	} else {
		copy(tdxNonce[:], opts.TEENonce)
	}
	return nil
}

func setTeeAttestationTdxQuote(quote any, attestation *pba.Attestation) error {
	switch q := quote.(type) {
	case *tpb.QuoteV4:
		attestation.TeeAttestation = &pba.Attestation_TdxAttestation{
			TdxAttestation: q,
		}
	default:
		return fmt.Errorf("unsupported quote type: %T", quote)
	}
	return nil
}

// Close will free resources held by QuoteProvider.
func (qp *TdxQuoteProvider) Close() error {
	return nil
}

type SevSnpDevice struct {
	Device sg.Device
}

func CreateSevSnpDevice() (*SevSnpDevice, error) {
	d, err := sg.OpenDevice()
	if err != nil {
		return nil, err
	}
	return &SevSnpDevice{Device: d}, nil
}
func (d *SevSnpDevice) AddAttestation(attestation *pba.Attestation, opts client.AttestOpts) error {
	var snpNonce [sabi.ReportDataSize]byte
	if len(opts.TEENonce) == 0 {
		copy(snpNonce[:], opts.Nonce)
	} else if len(opts.TEENonce) != sabi.ReportDataSize {
		return fmt.Errorf("the TEENonce size is %d. SEV-SNP device requires 64", len(opts.TEENonce))
	} else {
		copy(snpNonce[:], opts.TEENonce)
	}
	extReport, err := sg.GetExtendedReport(d.Device, snpNonce)
	if err != nil {
		return err
	}
	attestation.TeeAttestation = &pba.Attestation_SevSnpAttestation{
		SevSnpAttestation: extReport,
	}
	return nil
}

// Close will free the device handle held by the SevSnpDevice. Calling more
// than once has no effect.
func (d *SevSnpDevice) Close() error {
	if d.Device != nil {
		err := d.Device.Close()
		d.Device = nil
		return err
	}
	return nil
}

func getCertificateChain(k *client.Key, client *http.Client) ([][]byte, error) {
	var certs [][]byte
	currentCert := k.Cert()
	for len(certs) <= maxCertChainLength {
		issuingCert, err := fetchIssuingCertificate(client, currentCert)
		if err != nil {
			return nil, err
		}
		if issuingCert == nil {
			return certs, nil
		}
		certs = append(certs, issuingCert.Raw)
		currentCert = issuingCert
	}
	return nil, fmt.Errorf("max certificate chain length (%v) exceeded", maxCertChainLength)
}
func GetEventLog(rw io.ReadWriter) ([]byte, error) {
	if elg, ok := rw.(EventLogGetter); ok {
		return elg.EventLog()
	}
	return getRealEventLog()
}

func getRealEventLog() ([]byte, error) {
	return os.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}
func fetchIssuingCertificate(client *http.Client, cert *x509.Certificate) (*x509.Certificate, error) {
	// Check if we should event attempt fetching.
	if cert == nil || len(cert.IssuingCertificateURL) == 0 {
		return nil, nil
	}
	// For each URL, fetch and parse the certificate, then verify whether it signed cert.
	// If successful, return the parsed certificate. If any step in this process fails, try the next url.
	// If all the URLs fail, return the last error we got.
	// TODO(Issue #169): Return a multi-error here
	var lastErr error
	for i, url := range cert.IssuingCertificateURL {
		// Limit the number of attempts.
		if i >= maxIssuingCertificateURLs {
			break
		}
		resp, err := client.Get(url)
		if err != nil {
			lastErr = fmt.Errorf("failed to retrieve certificate at %v: %w", url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("certificate retrieval from %s returned non-OK status: %v", url, resp.StatusCode)
			continue
		}
		certBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body from %s: %w", url, err)
			continue
		}

		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse response from %s into a certificate: %w", url, err)
			continue
		}

		// Check if the parsed certificate signed the current one.
		if err = cert.CheckSignatureFrom(parsedCert); err != nil {
			lastErr = fmt.Errorf("parent certificate from %s did not sign child: %w", url, err)
			continue
		}
		return parsedCert, nil
	}
	return nil, lastErr
}

type EventLogGetter interface {
	EventLog() ([]byte, error)
}

func allocatedPCRs(rw io.ReadWriter) ([]tpm2.PCRSelection, error) {
	caps, moreData, err := tpm2.GetCapability(rw, tpm2.CapabilityPCRs, math.MaxUint32, 0)
	if err != nil {
		return nil, fmt.Errorf("listing implemented PCR banks: %w", err)
	}
	if moreData {
		return nil, fmt.Errorf("extra data from GetCapability")
	}
	var sels []tpm2.PCRSelection
	for _, cap := range caps {
		sel, ok := cap.(tpm2.PCRSelection)
		if !ok {
			return nil, fmt.Errorf("unexpected data from GetCapability")
		}
		// skip empty (unallocated) PCR selections
		if len(sel.PCRs) == 0 {
			continue
		}
		sels = append(sels, sel)
	}
	return sels, nil
}

func Quote(rw io.ReadWriter, k *client.Key, selpcr tpm2.PCRSelection, extraData []byte) (*pb.Quote, error) {
	// Make sure that we have a valid signing key before trying quote
	var err error
	if _, err = GetSigningHashAlg(k.PublicArea()); err != nil {
		return nil, err
	}
	if k.PublicArea().Attributes == tpm2.FlagRestricted {
		return nil, fmt.Errorf("unrestricted keys are insecure to use with Quote")
	}

	quote := &pb.Quote{}
	quote.Quote, quote.RawSig, err = tpm2.QuoteRaw(rw, k.Handle(), "", "", extraData, selpcr, tpm2.AlgNull)
	if err != nil {
		return nil, fmt.Errorf("failed to quote: %w", err)
	}
	quote.Pcrs, err = ReadPCRs(rw, selpcr)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %w", err)
	}
	// Verify the quote client-side to make sure we didn't mess things up.
	// NOTE: the quote still must be verified server-side as well.
	if err := VerifyQuote(quote, k.PublicKey(), extraData); err != nil {
		return nil, fmt.Errorf("failed to verify quote: %w", err)
	}
	return quote, nil
}

func GetSigningHashAlg(pubArea tpm2.Public) (tpm2.Algorithm, error) {
	if pubArea.Attributes&tpm2.FlagSign == 0 {
		return tpm2.AlgNull, fmt.Errorf("non-signing key used with signing operation")
	}

	var sigScheme *tpm2.SigScheme
	switch pubArea.Type {
	case tpm2.AlgRSA:
		sigScheme = pubArea.RSAParameters.Sign
	case tpm2.AlgECC:
		sigScheme = pubArea.ECCParameters.Sign
	default:
		return tpm2.AlgNull, fmt.Errorf("unsupported key type: %v", pubArea.Type)
	}

	if sigScheme == nil {
		return tpm2.AlgNull, fmt.Errorf("unsupported null signing scheme")
	}
	switch sigScheme.Alg {
	case tpm2.AlgRSAPSS, tpm2.AlgRSASSA, tpm2.AlgECDSA:
		return sigScheme.Hash, nil
	default:
		return tpm2.AlgNull, fmt.Errorf("unsupported signing algorithm: %v", sigScheme.Alg)
	}
}

func ReadPCRs(rw io.ReadWriter, sel tpm2.PCRSelection) (*pb.PCRs, error) {
	pl := pb.PCRs{
		Hash: pb.HashAlgo(sel.Hash),
		Pcrs: map[uint32][]byte{},
	}

	for i := 0; i < len(sel.PCRs); i += 8 {
		end := min(i+8, len(sel.PCRs))
		pcrSel := tpm2.PCRSelection{
			Hash: sel.Hash,
			PCRs: sel.PCRs[i:end],
		}

		pcrMap, err := tpm2.ReadPCRs(rw, pcrSel)
		if err != nil {
			return nil, err
		}

		for pcr, val := range pcrMap {
			pl.Pcrs[uint32(pcr)] = val
		}
	}

	return &pl, nil
}

var SignatureHashAlgs = []tpm2.Algorithm{tpm2.AlgSHA512, tpm2.AlgSHA384, tpm2.AlgSHA256}

// VerifyQuote performs the following checks to validate a Quote:
//   - the provided signature is generated by the trusted AK public key
//   - the signature signs the provided quote data
//   - the quote data starts with TPM_GENERATED_VALUE
//   - the quote data is a valid TPMS_QUOTE_INFO
//   - the quote data was taken over the provided PCRs
//   - the provided PCR values match the quote data internal digest
//   - the provided extraData matches that in the quote data
//   - the signature hash algorithm must be in HashAlgs
//
// Note that the caller must have already established trust in the provided
// public key before validating the Quote.
//
// VerifyQuote supports ECDSA and RSASSA signature verification.

func VerifyQuote(q *pb.Quote, trustedPub crypto.PublicKey, extraData []byte) error {
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(q.GetRawSig()))
	if err != nil {
		return fmt.Errorf("signature decoding failed: %v", err)
	}

	hash, err := verifyHashAlg(sig)
	if err != nil {
		return err
	}

	switch pub := trustedPub.(type) {
	case *ecdsa.PublicKey:
		if err = verifyECDSAQuoteSignature(pub, hash, q.GetQuote(), sig); err != nil {
			return err
		}
	case *rsa.PublicKey:
		if err = verifyRSAQuoteSignature(pub, hash, q.GetQuote(), sig); err != nil {
			return err
		}
	default:
		return fmt.Errorf("only RSA and ECC public keys are currently supported, received type: %T", pub)
	}

	// Decode and check for magic TPMS_GENERATED_VALUE.
	attestationData, err := tpm2.DecodeAttestationData(q.GetQuote())
	if err != nil {
		return fmt.Errorf("decoding attestation data failed: %v", err)
	}
	if attestationData.Type != tpm2.TagAttestQuote {
		return fmt.Errorf("expected quote tag, got: %v", attestationData.Type)
	}
	attestedQuoteInfo := attestationData.AttestedQuoteInfo
	if attestedQuoteInfo == nil {
		return fmt.Errorf("attestation data does not contain quote info")
	}
	if subtle.ConstantTimeCompare(attestationData.ExtraData, extraData) == 0 {
		return fmt.Errorf("quote extraData %v did not match expected extraData %v",
			attestationData.ExtraData, extraData)
	}
	return validatePCRDigest(attestedQuoteInfo, q.GetPcrs(), hash)
}

// Get the cryptographic hash used for the signature and make sure we support it
func verifyHashAlg(sig *tpm2.Signature) (crypto.Hash, error) {
	var hashAlg tpm2.Algorithm
	if sig.ECC != nil {
		hashAlg = sig.ECC.HashAlg
	} else if sig.RSA != nil {
		hashAlg = sig.RSA.HashAlg
	} else {
		return 0, fmt.Errorf("signature is missing hash algorithm")
	}

	// Convert from TPM2 hash algorithm to a Golang hash algorithm
	hash, err := hashAlg.Hash()
	if err != nil {
		return 0, err
	}
	for _, alg := range SignatureHashAlgs {
		if hashAlg == alg {
			return hash, nil
		}
	}
	return 0, fmt.Errorf("unsupported signature hash algorithm: %v", hash)
}

func verifyECDSAQuoteSignature(ecdsaPub *ecdsa.PublicKey, hash crypto.Hash, quoted []byte, sig *tpm2.Signature) error {
	if sig.Alg != tpm2.AlgECDSA {
		return fmt.Errorf("signature scheme 0x%x is not supported, only ECDSA is supported", sig.Alg)
	}

	hashConstructor := hash.New()
	hashConstructor.Write(quoted)
	if !ecdsa.Verify(ecdsaPub, hashConstructor.Sum(nil), sig.ECC.R, sig.ECC.S) {
		return fmt.Errorf("ECC signature verification failed")
	}
	return nil
}

func verifyRSAQuoteSignature(rsaPub *rsa.PublicKey, hash crypto.Hash, quoted []byte, sig *tpm2.Signature) error {
	if sig.Alg != tpm2.AlgRSASSA && sig.Alg != tpm2.AlgRSAPSS {
		return fmt.Errorf("signature scheme 0x%x is not supported, only RSASSA (PKCS#1 v1.5) and RSAPSS (PKCS#1 v2.1) are supported", sig.Alg)
	}
	switch sig.Alg {
	case tpm2.AlgRSASSA:
		hashConstructor := hash.New()
		hashConstructor.Write(quoted)
		if err := rsa.VerifyPKCS1v15(rsaPub, hash, hashConstructor.Sum(nil), sig.RSA.Signature); err != nil {
			return fmt.Errorf("RSASSA signature verification failed: %v", err)
		}
	case tpm2.AlgRSAPSS:
		hashConstructor := hash.New()
		hashConstructor.Write(quoted)
		if err := rsa.VerifyPSS(rsaPub, hash, hashConstructor.Sum(nil), sig.RSA.Signature, &rsa.PSSOptions{Hash: crypto.Hash(tpm2.AlgSHA256)}); err != nil {
			return fmt.Errorf("RSAPSS signature verification failed: %v", err)
		}
	}

	return nil
}

func validatePCRDigest(quoteInfo *tpm2.QuoteInfo, pcrs *pb.PCRs, hash crypto.Hash) error {
	if !SamePCRSelection(pcrs, quoteInfo.PCRSelection) {
		return fmt.Errorf("given PCRs and Quote do not have the same PCR selection")
	}
	pcrDigest := PCRDigest(pcrs, hash)
	if subtle.ConstantTimeCompare(quoteInfo.PCRDigest, pcrDigest) == 0 {
		return fmt.Errorf("given PCRs digest not matching")
	}
	return nil
}

func SamePCRSelection(p *pb.PCRs, sel tpm2.PCRSelection) bool {
	if tpm2.Algorithm(p.GetHash()) != sel.Hash {
		return false
	}
	if len(p.GetPcrs()) != len(sel.PCRs) {
		return false
	}
	for _, pcr := range sel.PCRs {
		if _, ok := p.Pcrs[uint32(pcr)]; !ok {
			return false
		}
	}
	return true
}
func PCRDigest(p *pb.PCRs, hashAlg crypto.Hash) []byte {
	hash := hashAlg.New()
	for i := uint32(0); i < 24; i++ {
		if pcrValue, exists := p.GetPcrs()[i]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}
