package utils_verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/go-attestation/attest"
	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sev "github.com/google/go-sev-guest/validate"
	sv "github.com/google/go-sev-guest/verify"
	tabi "github.com/google/go-tdx-guest/abi"
	tdx "github.com/google/go-tdx-guest/validate"
	tv "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tpm-tools/cel"
	pb "github.com/google/go-tpm-tools/proto/attest"
	pbt "github.com/google/go-tpm-tools/proto/tpm"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

var SignatureHashAlgs = []tpm2.Algorithm{tpm2.AlgSHA512, tpm2.AlgSHA384, tpm2.AlgSHA256}
var pcrHashAlgs = append(SignatureHashAlgs, tpm2.AlgSHA1)

var oidExtensionSubjectAltName = []int{2, 5, 29, 17}

var cloudComputeInstanceIdentifierOID asn1.ObjectIdentifier = []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 21}

var (
	// GCENonHostInfoSignature identifies the GCE Non-Host info event, which
	// indicates if memory encryption is enabled. This event is 32-bytes consisting
	// of the below signature (16 bytes), followed by a byte indicating whether
	// it is confidential, followed by 15 reserved bytes.
	GCENonHostInfoSignature = []byte("GCE NonHostInfo\x00")
	// GceVirtualFirmwarePrefix is the little-endian UCS-2 encoded string
	// "GCE Virtual Firmware v" without a null terminator. All GCE firmware
	// versions are UCS-2 encoded, start with this prefix, contain the firmware
	// version encoded as an integer, and end with a null terminator.
	GceVirtualFirmwarePrefix = []byte{0x47, 0x00, 0x43, 0x00,
		0x45, 0x00, 0x20, 0x00, 0x56, 0x00, 0x69, 0x00, 0x72, 0x00,
		0x74, 0x00, 0x75, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x20, 0x00,
		0x46, 0x00, 0x69, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x77, 0x00,
		0x61, 0x00, 0x72, 0x00, 0x65, 0x00, 0x20, 0x00, 0x76, 0x00}
)

// Standard Secure Boot certificates (DER encoded)
var (
	//go:embed secure-boot/GcePk.crt
	GceDefaultPKCert []byte
	//go:embed secure-boot/MicCorKEKCA2011_2011-06-24.crt
	MicrosoftKEKCA2011Cert []byte
	//go:embed secure-boot/MicWinProPCA2011_2011-10-19.crt
	WindowsProductionPCA2011Cert []byte
	//go:embed secure-boot/MicCorUEFCA2011_2011-06-27.crt
	MicrosoftUEFICA2011Cert []byte
)

var (
	newGrubKernelCmdlinePrefix = []byte("kernel_cmdline: ")
	oldGrubKernelCmdlinePrefix = []byte("grub_kernel_cmdline ")
	// See https://www.gnu.org/software/grub/manual/grub/grub.html#Measured-Boot.
	validPrefixes = [][]byte{[]byte("grub_cmd: "),
		newGrubKernelCmdlinePrefix,
		[]byte("module_cmdline: "),
		// Older style prefixes:
		// https://src.fedoraproject.org/rpms/grub2/blob/c789522f7cfa19a10cd716a1db24dab5499c6e5c/f/0224-Rework-TPM-measurements.patch
		oldGrubKernelCmdlinePrefix,
		[]byte("grub_cmd ")}
)

var defaultSevSnpGuestPolicy = sabi.SnpPolicy{
	SMT:       true,
	MigrateMA: true,
}

type gceSecurityProperties struct {
	SecurityVersion int64 `asn1:"explicit,tag:0,optional"`
	IsProduction    bool  `asn1:"explicit,tag:1,optional"`
}

type gceInstanceInfo struct {
	Zone               string `asn1:"utf8"`
	ProjectNumber      int64
	ProjectID          string `asn1:"utf8"`
	InstanceID         int64
	InstanceName       string                `asn1:"utf8"`
	SecurityProperties gceSecurityProperties `asn1:"explicit,optional"`
}

// GroupedError collects related errors and exposes them as a single error.
// Users can inspect the `Errors` field for details on the suberrors.
type GroupedError struct {
	// The prefix string returned by `Error()`, followed by the grouped errors.
	Prefix string
	Errors []error
}

// Error implements error.
func (g *GroupedError) Error() string {
	panic("unimplemented")
}

const (
	// UnsupportedLoader refers to a second-stage bootloader that is of an
	// unsupported type. VerifyAttestation will not parse the PCClient Event Log
	// for bootloader events.
	UnsupportedLoader Bootloader = iota
	// GRUB (https://www.gnu.org/software/grub/).
	GRUB
)

const (
	NoAction                   uint32 = 0x00000003
	Separator                  uint32 = 0x00000004
	EventTag                   uint32 = 0x00000006
	SCRTMVersion               uint32 = 0x00000008
	IPL                        uint32 = 0x0000000D
	NonhostInfo                uint32 = 0x00000011
	EFIBootServicesApplication uint32 = 0x80000003
	EFIAction                  uint32 = 0x80000007
)

const (
	// Measured when Boot Manager attempts to execute code from a Boot Option.
	CallingEFIApplication      string = "Calling EFI Application from Boot Option"
	ExitBootServicesInvocation string = "Exit Boot Services Invocation"
)

func VerifyAttestation(attestation *pb.Attestation, opts VerifyOpts) (*pb.MachineState, error) {
	if err := validateOpts(opts); err != nil {
		return nil, fmt.Errorf("bad options: %w", err)
	}

	var akPubKey crypto.PublicKey
	var machineState *pb.MachineState
	if len(attestation.GetAkCert()) == 0 {
		// If the AK Cert is not in the attestation, use the AK Public Area.
		akPubArea, err := tpm2.DecodePublic(attestation.GetAkPub())
		if err != nil {
			return nil, fmt.Errorf("failed to decode AK public area: %w", err)
		}
		akPubKey, err = akPubArea.Key()
		if err != nil {
			return nil, fmt.Errorf("failed to get AK public key: %w", err)
		}
		machineState, err = validateAKPub(akPubKey, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to validate AK public key: %w", err)
		}
	} else {
		// If AK Cert is presented, ignore the AK Public Area.
		akCert, err := x509.ParseCertificate(attestation.GetAkCert())
		if err != nil {
			return nil, fmt.Errorf("failed to parse AK certificate: %w", err)
		}
		// Use intermediate certs from the attestation if they exist.
		certs, err := parseCerts(attestation.IntermediateCerts)
		if err != nil {
			return nil, fmt.Errorf("attestation intermediates: %w", err)
		}
		opts.IntermediateCerts = append(opts.IntermediateCerts, certs...)

		machineState, err = validateAKCert(akCert, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to validate AK certificate: %w", err)
		}
		akPubKey = akCert.PublicKey.(crypto.PublicKey)
	}

	// Attempt to replay the log against our PCRs in order of hash preference
	var lastErr error
	for _, quote := range supportedQuotes(attestation.GetQuotes()) {
		// Verify the Quote
		if err := VerifyQuote(quote, akPubKey, opts.Nonce); err != nil {
			lastErr = fmt.Errorf("failed to verify quote: %w", err)
			continue
		}

		// Parse event logs and replay the events against the provided PCRs
		pcrs := quote.GetPcrs()
		state, err := parsePCClientEventLog(attestation.GetEventLog(), pcrs, opts.Loader)
		if err != nil {
			lastErr = fmt.Errorf("failed to validate the PCClient event log: %v", err)
			continue
		}

		if err := VerifyGceTechnology(attestation, state.Platform.GetTechnology(), &opts); err != nil {
			lastErr = fmt.Errorf("failed to verify memory encryption technology: %w", err)
			continue
		}

		celState, err := parseCanonicalEventLog(attestation.GetCanonicalEventLog(), pcrs)
		if err != nil {
			lastErr = fmt.Errorf("failed to validate the Canonical event log: %w", err)
			continue
		}

		// Verify the PCR hash algorithm. We have this check here (instead of at
		// the start of the loop) so that the user gets a "SHA-1 not supported"
		// error only if allowing SHA-1 support would actually allow the log
		// to be verified. This makes debugging failed verifications easier.
		if !opts.AllowSHA1 && tpm2.Algorithm(pcrs.GetHash()) == tpm2.AlgSHA1 {
			lastErr = fmt.Errorf("SHA-1 is not allowed for verification (set VerifyOpts.AllowSHA1 to true to allow)")
			continue
		}

		proto.Merge(machineState, celState)
		proto.Merge(machineState, state)

		return machineState, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("attestation does not contain a supported quote")
}

func VerifyQuote(q *pbt.Quote, trustedPub crypto.PublicKey, extraData []byte) error {
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

func validatePCRDigest(quoteInfo *tpm2.QuoteInfo, pcrs *pbt.PCRs, hash crypto.Hash) error {
	if !SamePCRSelection(pcrs, quoteInfo.PCRSelection) {
		return fmt.Errorf("given PCRs and Quote do not have the same PCR selection")
	}
	pcrDigest := PCRDigest(pcrs, hash)
	if subtle.ConstantTimeCompare(quoteInfo.PCRDigest, pcrDigest) == 0 {
		return fmt.Errorf("given PCRs digest not matching")
	}
	return nil

}

func SamePCRSelection(p *pbt.PCRs, sel tpm2.PCRSelection) bool {
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

func PCRDigest(p *pbt.PCRs, hashAlg crypto.Hash) []byte {
	hash := hashAlg.New()
	for i := uint32(0); i < 24; i++ {
		if pcrValue, exists := p.GetPcrs()[i]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}

type VerifyOpts struct {
	// The nonce used when calling client.Attest
	Nonce []byte

	TrustedAKs []crypto.PublicKey

	AllowSHA1 bool

	TrustedRootCerts  []*x509.Certificate
	IntermediateCerts []*x509.Certificate

	Loader Bootloader

	TEEOpts interface{}
}

// Bootloader refers to the second-stage bootloader that loads and transfers
// execution to the OS kernel.
type Bootloader int

func validateOpts(opts VerifyOpts) error {
	checkPub := len(opts.TrustedAKs) > 0
	checkCert := len(opts.TrustedRootCerts) > 0
	if !checkPub && !checkCert {
		return fmt.Errorf("no trust mechanism provided, either use TrustedAKs or TrustedRootCerts")
	}
	if checkPub && checkCert {
		return fmt.Errorf("multiple trust mechanisms provided, only use one of TrustedAKs or TrustedRootCerts")
	}
	return nil
}

func validateAKPub(ak crypto.PublicKey, opts VerifyOpts) (*pb.MachineState, error) {
	for _, trusted := range opts.TrustedAKs {
		if PubKeysEqual(ak, trusted) {
			return &pb.MachineState{}, nil
		}
	}
	return nil, fmt.Errorf("key not trusted")
}
func PubKeysEqual(k1 crypto.PublicKey, k2 crypto.PublicKey) bool {
	// Common interface for all the standard public key types, see:
	// https://pkg.go.dev/crypto@go1.18beta1#PublicKey
	type publicKey interface {
		Equal(crypto.PublicKey) bool
	}
	if key, ok := k1.(publicKey); ok {
		return key.Equal(k2)
	}
	return false
}

func parseCerts(rawCerts [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, certBytes := range rawCerts {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cert: %w", err)
		}
		certs[i] = cert
	}
	return certs, nil
}

func validateAKCert(akCert *x509.Certificate, opts VerifyOpts) (*pb.MachineState, error) {
	if len(opts.TrustedRootCerts) == 0 {
		return validateAKPub(akCert.PublicKey.(crypto.PublicKey), opts)
	}

	// We manually handle the SAN extension because x509 marks it unhandled if
	// SAN does not parse any of DNSNames, EmailAddresses, IPAddresses, or URIs.
	// https://cs.opensource.google/go/go/+/master:src/crypto/x509/parser.go;l=668-678
	var exts []asn1.ObjectIdentifier
	for _, ext := range akCert.UnhandledCriticalExtensions {
		if ext.Equal(oidExtensionSubjectAltName) {
			continue
		}
		exts = append(exts, ext)
	}
	akCert.UnhandledCriticalExtensions = exts

	x509Opts := x509.VerifyOptions{
		Roots:         makePool(opts.TrustedRootCerts),
		Intermediates: makePool(opts.IntermediateCerts),
		// The default key usage (ExtKeyUsageServerAuth) is not appropriate for
		// an Attestation Key: ExtKeyUsage of
		// - https://oidref.com/2.23.133.8.1
		// - https://oidref.com/2.23.133.8.3
		// https://pkg.go.dev/crypto/x509#VerifyOptions
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}
	if _, err := akCert.Verify(x509Opts); err != nil {
		return nil, fmt.Errorf("certificate did not chain to a trusted root: %v", err)
	}

	instanceInfo, err := getInstanceInfoFromExtensions(akCert.Extensions)
	if err != nil {
		return nil, fmt.Errorf("error getting instance info: %v", err)
	}

	return &pb.MachineState{Platform: &pb.PlatformState{InstanceInfo: instanceInfo}}, nil
}

func makePool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
func getInstanceInfoFromExtensions(extensions []pkix.Extension) (*pb.GCEInstanceInfo, error) {
	var rawInfo []byte
	for _, ext := range extensions {
		if ext.Id.Equal(cloudComputeInstanceIdentifierOID) {
			rawInfo = ext.Value
			break
		}
	}

	// If GCE Instance Info extension is not found.
	if len(rawInfo) == 0 {
		return nil, nil
	}

	info := gceInstanceInfo{}
	if _, err := asn1.Unmarshal(rawInfo, &info); err != nil {
		return nil, fmt.Errorf("failed to parse GCE Instance Information Extension: %w", err)
	}

	// TODO: Remove when fields are changed to uint64.
	if info.ProjectNumber < 0 || info.InstanceID < 0 || info.SecurityProperties.SecurityVersion < 0 {
		return nil, fmt.Errorf("negative integer fields found in GCE Instance Information Extension")
	}

	// Check production.
	if !info.SecurityProperties.IsProduction {
		return nil, nil
	}

	return &pb.GCEInstanceInfo{
		Zone:          info.Zone,
		ProjectId:     info.ProjectID,
		ProjectNumber: uint64(info.ProjectNumber),
		InstanceName:  info.InstanceName,
		InstanceId:    uint64(info.InstanceID),
	}, nil
}

func supportedQuotes(quotes []*tpmpb.Quote) []*tpmpb.Quote {
	out := make([]*tpmpb.Quote, 0, len(quotes))
	for _, alg := range pcrHashAlgs {
		for _, quote := range quotes {
			if tpm2.Algorithm(quote.GetPcrs().GetHash()) == alg {
				out = append(out, quote)
				break
			}
		}
	}
	return out
}

func parsePCClientEventLog(rawEventLog []byte, pcrs *tpmpb.PCRs, loader Bootloader) (*pb.MachineState, error) {
	var errors []error
	events, err := parseReplayHelper(rawEventLog, pcrs)
	if err != nil {
		return nil, createGroupedError("", []error{err})
	}
	// error is already checked in convertToAttestPcrs
	cryptoHash, _ := tpm2.Algorithm(pcrs.GetHash()).Hash()

	rawEvents := convertToPbEvents(cryptoHash, events)
	platform, err := getPlatformState(cryptoHash, rawEvents)
	if err != nil {
		errors = append(errors, err)
	}
	/*sbState, err := getSecureBootState(events)
	if err != nil {
		errors = append(errors, err)
	}*/
	/*efiState, err := getEfiState(cryptoHash, rawEvents)
	if err != nil {
		errors = append(errors, err)
		fmt.Println("CCCCC")
	}*/

	var grub *pb.GrubState
	var kernel *pb.LinuxKernelState
	if loader == GRUB {
		grub, err = getGrubState(cryptoHash, rawEvents)
		if err != nil {
			errors = append(errors, err)
			fmt.Println("DDDDD")
		}
		kernel, err = getLinuxKernelStateFromGRUB(grub)
		if err != nil {
			errors = append(errors, err)
			fmt.Println("EEEEE")
		}
	}

	return &pb.MachineState{
		Platform:    platform,
		//SecureBoot:  sbState,
		//Efi:         efiState,
		RawEvents:   rawEvents,
		Hash:        pcrs.GetHash(),
		Grub:        grub,
		LinuxKernel: kernel,
	}, createGroupedError("failed to fully parse MachineState:", errors)
}

func parseCanonicalEventLog(rawCanonicalEventLog []byte, pcrs *tpmpb.PCRs) (*pb.MachineState, error) {
	decodedCEL, err := cel.DecodeToCEL(bytes.NewBuffer(rawCanonicalEventLog))
	if err != nil {
		return nil, err
	}
	// Validate the COS event log first.
	if err := decodedCEL.Replay(pcrs); err != nil {
		return nil, err
	}

	cosState, err := getVerifiedCosState(decodedCEL)
	if err != nil {
		return nil, err
	}

	return &pb.MachineState{
		Cos: cosState,
	}, err
}

func getVerifiedCosState(coscel cel.CEL) (*pb.AttestedCosState, error) {
	cosState := &pb.AttestedCosState{}
	cosState.Container = &pb.ContainerState{}
	cosState.HealthMonitoring = &pb.HealthMonitoringState{}
	cosState.Container.Args = make([]string, 0)
	cosState.Container.EnvVars = make(map[string]string)
	cosState.Container.OverriddenEnvVars = make(map[string]string)

	seenSeparator := false
	for _, record := range coscel.Records {
		// COS State only comes from the CosEventPCR
		if record.PCR != cel.CosEventPCR {
			return nil, fmt.Errorf("found unexpected PCR %d in CEL log", record.PCR)
		}

		// The Content.Type is not verified at this point, so we have to fail
		// if we see any events that we do not understand. This ensures that
		// we either verify the digest of event event in this PCR, or we fail
		// to replay the event log.
		// TODO: See if we can fix this to have the Content Type be verified.
		cosTlv, err := record.Content.ParseToCosTlv()
		if err != nil {
			return nil, err
		}

		// verify digests for the cos cel content
		if err := cel.VerifyDigests(cosTlv, record.Digests); err != nil {
			return nil, err
		}

		// TODO: Add support for post-separator container data
		if seenSeparator {
			return nil, fmt.Errorf("found COS Event Type %v after LaunchSeparator event", cosTlv.EventType)
		}

		switch cosTlv.EventType {
		case cel.ImageRefType:
			if cosState.Container.GetImageReference() != "" {
				return nil, fmt.Errorf("found more than one ImageRef event")
			}
			cosState.Container.ImageReference = string(cosTlv.EventContent)

		case cel.ImageDigestType:
			if cosState.Container.GetImageDigest() != "" {
				return nil, fmt.Errorf("found more than one ImageDigest event")
			}
			cosState.Container.ImageDigest = string(cosTlv.EventContent)

		case cel.RestartPolicyType:
			restartPolicy, ok := pb.RestartPolicy_value[string(cosTlv.EventContent)]
			if !ok {
				return nil, fmt.Errorf("unknown restart policy in COS eventlog: %s", string(cosTlv.EventContent))
			}
			cosState.Container.RestartPolicy = pb.RestartPolicy(restartPolicy)

		case cel.ImageIDType:
			if cosState.Container.GetImageId() != "" {
				return nil, fmt.Errorf("found more than one ImageId event")
			}
			cosState.Container.ImageId = string(cosTlv.EventContent)

		case cel.EnvVarType:
			envName, envVal, err := cel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.EnvVars[envName] = envVal

		case cel.ArgType:
			cosState.Container.Args = append(cosState.Container.Args, string(cosTlv.EventContent))

		case cel.OverrideArgType:
			cosState.Container.OverriddenArgs = append(cosState.Container.OverriddenArgs, string(cosTlv.EventContent))

		case cel.OverrideEnvType:
			envName, envVal, err := cel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.OverriddenEnvVars[envName] = envVal
		case cel.LaunchSeparatorType:
			seenSeparator = true
		case cel.MemoryMonitorType:
			enabled := false
			if len(cosTlv.EventContent) == 1 && cosTlv.EventContent[0] == uint8(1) {
				enabled = true
			}
			cosState.HealthMonitoring.MemoryEnabled = &enabled
		default:
			return nil, fmt.Errorf("found unknown COS Event Type %v", cosTlv.EventType)
		}

	}
	return cosState, nil
}

func parseReplayHelper(rawEventLog []byte, pcrs *tpmpb.PCRs) ([]attest.Event, error) {
	// Similar to ParseCosCanonicalEventLogPCR, just return an empty array of events for an empty log
	if len(rawEventLog) == 0 {
		return nil, nil
	}

	attestPcrs, err := convertToAttestPcrs(pcrs)
	if err != nil {
		return nil, fmt.Errorf("received bad PCR proto: %v", err)
	}
	eventLog, err := attest.ParseEventLog(rawEventLog)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event log: %v", err)
	}
	events, err := eventLog.Verify(attestPcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to replay event log: %v", err)
	}
	return events, nil
}

func convertToAttestPcrs(pcrProto *tpmpb.PCRs) ([]attest.PCR, error) {
	hash := tpm2.Algorithm(pcrProto.GetHash())
	cryptoHash, err := hash.Hash()
	if err != nil {
		return nil, err
	}

	attestPcrs := make([]attest.PCR, 0, len(pcrProto.GetPcrs()))
	for index, digest := range pcrProto.GetPcrs() {
		attestPcrs = append(attestPcrs, attest.PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: cryptoHash,
		})
	}
	return attestPcrs, nil
}

func createGroupedError(prefix string, errors []error) error {
	if len(errors) == 0 {
		return nil
	}
	return &GroupedError{Prefix: prefix, Errors: errors}
}
func convertToPbEvents(hash crypto.Hash, events []attest.Event) []*pb.Event {
	pbEvents := make([]*pb.Event, len(events))
	for i, event := range events {
		hasher := hash.New()
		hasher.Write(event.Data)
		digest := hasher.Sum(nil)

		pbEvents[i] = &pb.Event{
			PcrIndex:       uint32(event.Index),
			UntrustedType:  uint32(event.Type),
			Data:           event.Data,
			Digest:         event.Digest,
			DigestVerified: bytes.Equal(digest, event.Digest),
		}
	}
	return pbEvents
}

func getPlatformState(hash crypto.Hash, events []*pb.Event) (*pb.PlatformState, error) {
	// We pre-compute the separator and EFI Action event hash.
	// We check if these events have been modified, since the event type is
	// untrusted.
	sepInfo := getSeparatorInfo(hash)
	var versionString []byte
	var nonHostInfo []byte
	for _, event := range events {
		index := event.GetPcrIndex()
		if index != 0 {
			continue
		}
		evtType := event.GetUntrustedType()

		isSeparator, err := checkIfValidSeparator(event, sepInfo)
		if err != nil {
			return nil, err
		}
		if isSeparator {
			// Don't trust any PCR0 events after the separator
			break
		}

		if evtType == SCRTMVersion {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid SCRTM version event for PCR%d", index)
			}
			versionString = event.GetData()
		}

		if evtType == NonhostInfo {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid Non-Host info event for PCR%d", index)
			}
			nonHostInfo = event.GetData()
		}
	}

	state := &pb.PlatformState{}
	if gceVersion, err := ConvertSCRTMVersionToGCEFirmwareVersion(versionString); err == nil {
		state.Firmware = &pb.PlatformState_GceVersion{GceVersion: gceVersion}
	} else {
		state.Firmware = &pb.PlatformState_ScrtmVersionId{ScrtmVersionId: versionString}
	}

	if tech, err := ParseGCENonHostInfo(nonHostInfo); err == nil {
		state.Technology = tech
	}

	return state, nil
}

type separatorInfo struct {
	separatorData    [][]byte
	separatorDigests [][]byte
}

func getSeparatorInfo(hash crypto.Hash) *separatorInfo {
	hasher := hash.New()
	// From the PC Client Firmware Profile spec, on the separator event:
	// The event field MUST contain the hex value 00000000h or FFFFFFFFh.
	sepData := [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}}
	sepDigests := make([][]byte, 0, len(sepData))
	for _, value := range sepData {
		hasher.Write(value)
		sepDigests = append(sepDigests, hasher.Sum(nil))
	}
	return &separatorInfo{separatorData: sepData, separatorDigests: sepDigests}
}

func checkIfValidSeparator(event *pb.Event, sepInfo *separatorInfo) (bool, error) {
	evtType := event.GetUntrustedType()
	index := event.GetPcrIndex()
	if (evtType != Separator) && !contains(sepInfo.separatorDigests, event.GetDigest()) {
		return false, nil
	}
	// To make sure we have a valid event, we check any event (e.g., separator)
	// that claims to be of the event type or "looks like" the event to prevent
	// certain vulnerabilities in event parsing. For more info see:
	// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
	if evtType != Separator {
		return false, fmt.Errorf("PCR%d event contains separator data but non-separator type %d", index, evtType)
	}
	if !event.GetDigestVerified() {
		return false, fmt.Errorf("unverified separator digest for PCR%d", index)
	}
	if !contains(sepInfo.separatorData, event.GetData()) {
		return false, fmt.Errorf("invalid separator data for PCR%d", index)
	}
	return true, nil
}

func contains(set [][]byte, value []byte) bool {
	for _, setItem := range set {
		if bytes.Equal(value, setItem) {
			return true
		}
	}
	return false
}

func ConvertSCRTMVersionToGCEFirmwareVersion(version []byte) (uint32, error) {
	prefixLen := len(GceVirtualFirmwarePrefix)
	if (len(version) <= prefixLen) || (len(version)%2 != 0) {
		return 0, fmt.Errorf("length of GCE version (%d) is invalid", len(version))
	}
	if !bytes.Equal(version[:prefixLen], GceVirtualFirmwarePrefix) {
		return 0, errors.New("prefix for GCE version is missing")
	}
	asciiVersion := []byte{}
	for i, b := range version[prefixLen:] {
		// Skip the UCS-2 null bytes and the null terminator
		if b == '\x00' {
			continue
		}
		// All odd bytes in our UCS-2 string should be Null
		if i%2 != 0 {
			return 0, errors.New("invalid UCS-2 in the version string")
		}
		asciiVersion = append(asciiVersion, b)
	}

	versionNum, err := strconv.ParseUint(string(asciiVersion), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("when parsing GCE firmware version: %w", err)
	}
	return uint32(versionNum), nil
}

func ParseGCENonHostInfo(nonHostInfo []byte) (pb.GCEConfidentialTechnology, error) {
	prefixLen := len(GCENonHostInfoSignature)
	if len(nonHostInfo) < (prefixLen + 1) {
		return pb.GCEConfidentialTechnology_NONE, fmt.Errorf("length of GCE Non-Host info (%d) is too short", len(nonHostInfo))
	}

	if !bytes.Equal(nonHostInfo[:prefixLen], GCENonHostInfoSignature) {
		return pb.GCEConfidentialTechnology_NONE, errors.New("prefix for GCE Non-Host info is missing")
	}
	tech := nonHostInfo[prefixLen]
	if tech > byte(pb.GCEConfidentialTechnology_AMD_SEV_SNP) {
		return pb.GCEConfidentialTechnology_NONE, fmt.Errorf("unknown GCE Confidential Technology: %d", tech)
	}
	return pb.GCEConfidentialTechnology(tech), nil
}

func getSecureBootState(attestEvents []attest.Event) (*pb.SecureBootState, error) {
	attestSbState, err := attest.ParseSecurebootState(attestEvents)
	if err != nil {
		fmt.Printf("failed to parse SecureBootState: %v", err)
		return nil, fmt.Errorf("failed to parse SecureBootState: %v", err)
	}
	if len(attestSbState.PreSeparatorAuthority) != 0 {
		fmt.Println("BBBBB22222")
		return nil, fmt.Errorf("event log contained %v pre-separator authorities, which are not expected or supported", len(attestSbState.PreSeparatorAuthority))
	}
	return &pb.SecureBootState{
		Enabled:   attestSbState.Enabled,
		Db:        convertToPbDatabase(attestSbState.PermittedKeys, attestSbState.PermittedHashes),
		Dbx:       convertToPbDatabase(attestSbState.ForbiddenKeys, attestSbState.ForbiddenHashes),
		Authority: convertToPbDatabase(attestSbState.PostSeparatorAuthority, nil),
	}, nil
}

func convertToPbDatabase(certs []x509.Certificate, hashes [][]byte) *pb.Database {
	protoCerts := make([]*pb.Certificate, 0, len(certs))
	for _, cert := range certs {
		wkEnum, err := matchWellKnown(cert)
		var pbCert pb.Certificate
		if err == nil {
			pbCert.Representation = &pb.Certificate_WellKnown{WellKnown: wkEnum}
		} else {
			pbCert.Representation = &pb.Certificate_Der{Der: cert.Raw}
		}
		protoCerts = append(protoCerts, &pbCert)
	}
	return &pb.Database{
		Certs:  protoCerts,
		Hashes: hashes,
	}
}

func matchWellKnown(cert x509.Certificate) (pb.WellKnownCertificate, error) {
	if bytes.Equal(WindowsProductionPCA2011Cert, cert.Raw) {
		return pb.WellKnownCertificate_MS_WINDOWS_PROD_PCA_2011, nil
	}
	if bytes.Equal(MicrosoftUEFICA2011Cert, cert.Raw) {
		return pb.WellKnownCertificate_MS_THIRD_PARTY_UEFI_CA_2011, nil
	}
	return pb.WellKnownCertificate_UNKNOWN, errors.New("failed to find matching well known certificate")
}

func getEfiState(hash crypto.Hash, events []*pb.Event) (*pb.EfiState, error) {
	// We pre-compute various event digests, and check if those event type have
	// been modified. We only trust events that come before the
	// ExitBootServices() request.
	separatorInfo := getSeparatorInfo(hash)

	hasher := hash.New()
	hasher.Write([]byte(CallingEFIApplication))
	callingEFIAppDigest := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write([]byte(ExitBootServicesInvocation))
	exitBootSvcDigest := hasher.Sum(nil)

	var efiAppStates []*pb.EfiApp
	var seenSeparator4 bool
	var seenSeparator5 bool
	var seenCallingEfiApp bool
	var seenExitBootServices bool
	for _, event := range events {
		index := event.GetPcrIndex()
		// getEfiState should only ever process PCRs 4 and 5.
		if index != 4 && index != 5 {
			continue
		}
		evtType := event.GetUntrustedType()

		switch index {
		case 4:
			// Process Calling EFI Application event.
			if bytes.Equal(callingEFIAppDigest, event.GetDigest()) {
				if evtType != EFIAction {
					return nil, fmt.Errorf("PCR%d contains CallingEFIApp event but non EFIAction type: %d",
						index, evtType)
				}
				if !event.GetDigestVerified() {
					return nil, fmt.Errorf("unverified CallingEFIApp digest for PCR%d", index)
				}
				// We don't support calling more than one boot device.
				if seenCallingEfiApp {
					return nil, fmt.Errorf("found duplicate CallingEFIApp event in PCR%d", index)
				}
				if seenSeparator4 {
					return nil, fmt.Errorf("found CallingEFIApp event in PCR%d after separator event", index)
				}
				seenCallingEfiApp = true
			}

			if evtType == EFIBootServicesApplication {
				if !seenCallingEfiApp {
					return nil, fmt.Errorf("found EFIBootServicesApplication in PCR%d before CallingEFIApp event", index)
				}
				efiAppStates = append(efiAppStates, &pb.EfiApp{Digest: event.GetDigest()})
			}

			isSeparator, err := checkIfValidSeparator(event, separatorInfo)
			if err != nil {
				return nil, err
			}
			if !isSeparator {
				continue
			}
			if seenSeparator4 {
				return nil, errors.New("found duplicate Separator event in PCR4")
			}
			seenSeparator4 = true
		case 5:
			// Process ExitBootServices event.
			if bytes.Equal(exitBootSvcDigest, event.GetDigest()) {
				if evtType != EFIAction {
					return nil, fmt.Errorf("PCR%d contains ExitBootServices event but non EFIAction type: %d",
						index, evtType)
				}
				if !event.GetDigestVerified() {
					return nil, fmt.Errorf("unverified ExitBootServices digest for PCR%d", index)
				}
				// Don't process any PCR4 or PCR5 events after Boot Manager has
				// requested ExitBootServices().
				seenExitBootServices = true
				break
			}

			isSeparator, err := checkIfValidSeparator(event, separatorInfo)
			if err != nil {
				return nil, err
			}
			if !isSeparator {
				continue
			}
			if seenSeparator5 {
				return nil, errors.New("found duplicate Separator event in PCR5")
			}
			seenSeparator5 = true
		}
	}
	// Only write EFI digests if we see an ExitBootServices invocation.
	// Otherwise, software further down the bootchain could extend bad
	// PCR4 measurements.
	if seenExitBootServices {
		return &pb.EfiState{Apps: efiAppStates}, nil
	}
	return nil, nil
}

func getGrubState(hash crypto.Hash, events []*pb.Event) (*pb.GrubState, error) {
	var files []*pb.GrubFile
	var commands []string
	for idx, event := range events {
		index := event.GetPcrIndex()
		if index != 8 && index != 9 {
			continue
		}

		// Skip parsing EV_EVENT_TAG event since it likely comes from Linux.
		if event.GetUntrustedType() == EventTag {
			continue
		}

		if event.GetUntrustedType() != IPL {
			return nil, fmt.Errorf("invalid event type for PCR%d, expected EV_IPL", index)
		}

		if index == 9 {
			files = append(files, &pb.GrubFile{Digest: event.GetDigest(),
				UntrustedFilename: event.GetData()})
		} else if index == 8 {
			hasher := hash.New()
			suffixAt := -1
			rawData := event.GetData()
			for _, prefix := range validPrefixes {
				if bytes.HasPrefix(rawData, prefix) {
					suffixAt = len(prefix)
					break
				}
			}
			if suffixAt == -1 {
				return nil, fmt.Errorf("invalid prefix seen for PCR%d event: %s", index, rawData)
			}
			hasher.Write(rawData[suffixAt : len(rawData)-1])
			if !bytes.Equal(event.Digest, hasher.Sum(nil)) {
				// Older GRUBs measure "grub_cmd " with the null terminator.
				// However, "grub_kernel_cmdline " measurements also ignore the null terminator.
				hasher.Reset()
				hasher.Write(rawData[suffixAt:])
				if !bytes.Equal(event.Digest, hasher.Sum(nil)) {
					return nil, fmt.Errorf("invalid digest seen for GRUB event log in event %d: %s", idx, hex.EncodeToString(event.Digest))
				}
			}
			hasher.Reset()
			commands = append(commands, string(rawData))
		}
	}
	if len(files) == 0 && len(commands) == 0 {
		return nil, errors.New("no GRUB measurements found")
	}
	return &pb.GrubState{Files: files, Commands: commands}, nil
}
func getLinuxKernelStateFromGRUB(grub *pb.GrubState) (*pb.LinuxKernelState, error) {
	var cmdline string
	seen := false

	for _, command := range grub.GetCommands() {
		// GRUB config is always in UTF-8: https://www.gnu.org/software/grub/manual/grub/html_node/Internationalisation.html.
		cmdBytes := []byte(command)
		suffixAt := getGrubKernelCmdlineSuffix(cmdBytes)
		if suffixAt == -1 {
			continue
		}

		if seen {
			return nil, fmt.Errorf("more than one kernel commandline in GRUB commands")
		}
		seen = true
		cmdline = command[suffixAt:]
	}

	return &pb.LinuxKernelState{CommandLine: cmdline}, nil
}
func getGrubKernelCmdlineSuffix(grubCmd []byte) int {
	for _, prefix := range [][]byte{oldGrubKernelCmdlinePrefix, newGrubKernelCmdlinePrefix} {
		if bytes.HasPrefix(grubCmd, prefix) {
			return len(prefix)
		}
	}
	return -1
}

type VerifySnpOpts struct {
	Validation   *sev.Options
	Verification *sv.Options
}
type VerifyTdxOpts struct {
	Validation   *tdx.Options
	Verification *tv.Options
}

func SevSnpDefaultOptions(tpmNonce []byte) *VerifySnpOpts {
	return &VerifySnpOpts{
		Validation:   SevSnpDefaultValidateOpts(tpmNonce),
		Verification: sv.DefaultOptions(),
	}
}
func SevSnpDefaultValidateOpts(tpmNonce []byte) *sev.Options {
	policy := &sev.Options{GuestPolicy: defaultSevSnpGuestPolicy}
	policy.ReportData = make([]byte, sabi.ReportDataSize)
	copy(policy.ReportData, tpmNonce)
	return policy
}
func VerifySevSnpAttestation(attestation *spb.Attestation, opts *VerifySnpOpts) error {
	// Check that the report is signed by a valid AMD key. Do not check revocations. This must be
	// done before validation to ensure the certificates are filled in by the verify library.
	if err := sv.SnpAttestation(attestation, opts.Verification); err != nil {
		return err
	}
	// Check that the fields of the report are acceptable.
	return sev.SnpAttestation(attestation, opts.Validation)
}
func TdxDefaultValidateOpts(tdxNonce []byte) *tdx.Options {
	policy := &tdx.Options{HeaderOptions: tdx.HeaderOptions{},
		TdQuoteBodyOptions: tdx.TdQuoteBodyOptions{}}
	policy.TdQuoteBodyOptions.ReportData = make([]byte, tabi.ReportDataSize)
	copy(policy.TdQuoteBodyOptions.ReportData, tdxNonce)
	return policy
}
func TdxDefaultOptions(tdxNonce []byte) *VerifyTdxOpts {
	return &VerifyTdxOpts{
		Validation:   TdxDefaultValidateOpts(tdxNonce),
		Verification: tv.DefaultOptions(),
	}
}
func VerifyTdxAttestation(tdxAttestationQuote any, opts *VerifyTdxOpts) error {
	// Check that the quote contains valid signature and certificates. Do not check revocations.
	if err := tv.TdxQuote(tdxAttestationQuote, opts.Verification); err != nil {
		return err
	}
	// Check that the fields of the quote are acceptable
	return tdx.TdxQuote(tdxAttestationQuote, opts.Validation)
}
func VerifyGceTechnology(attestation *pb.Attestation, tech pb.GCEConfidentialTechnology, opts *VerifyOpts) error {
	switch tech {
	case pb.GCEConfidentialTechnology_NONE: // Nothing to verify
		if opts.TEEOpts != nil {
			return fmt.Errorf("memory encryption technology %v does not support TEEOpts", tech)
		}
		return nil
	case pb.GCEConfidentialTechnology_AMD_SEV: // Not verifiable on GCE
		if opts.TEEOpts != nil {
			return fmt.Errorf("memory encryption technology %v does not support TEEOpts", tech)
		}
		return nil
	case pb.GCEConfidentialTechnology_AMD_SEV_ES: // Not verifiable on GCE
		if opts.TEEOpts != nil {
			return fmt.Errorf("memory encryption technology %v does not support TEEOpts", tech)
		}
		return nil
	case pb.GCEConfidentialTechnology_AMD_SEV_SNP:
		var snpOpts *VerifySnpOpts
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_SevSnpAttestation)
		if !ok {
			return fmt.Errorf("TEE attestation is %T, expected a SevSnpAttestation", attestation.GetTeeAttestation())
		}
		if opts.TEEOpts == nil {
			snpOpts = SevSnpDefaultOptions(opts.Nonce)
		} else {
			snpOpts, ok = opts.TEEOpts.(*VerifySnpOpts)
			if !ok {
				return fmt.Errorf("unexpected value for TEEOpts given a SEV-SNP attestation report: %v",
					opts.TEEOpts)
			}
		}
		return VerifySevSnpAttestation(tee.SevSnpAttestation, snpOpts)
	case pb.GCEConfidentialTechnology_INTEL_TDX:
		var tdxOpts *VerifyTdxOpts
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_TdxAttestation)
		if !ok {
			return fmt.Errorf("TEE attestation is %T, expected a TdxAttestation", attestation.GetTeeAttestation())
		}
		if opts.TEEOpts == nil {
			tdxOpts = TdxDefaultOptions(opts.Nonce)
		} else {
			tdxOpts, ok = opts.TEEOpts.(*VerifyTdxOpts)
			if !ok {
				return fmt.Errorf("unexpected value for TEEOpts given a TDX attestation quote: %v", opts.TEEOpts)
			}
		}
		return VerifyTdxAttestation(tee.TdxAttestation, tdxOpts)
	}
	return fmt.Errorf("unknown GCEConfidentialTechnology: %v", tech)
}
