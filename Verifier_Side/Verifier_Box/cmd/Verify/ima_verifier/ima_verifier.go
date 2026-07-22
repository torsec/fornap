package ima_verifier

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/veraison/corim/comid"
	"github.com/google/uuid"
)

const COLON_BYTE = byte(58) // ASCII code for ":"
const NULL_BYTE = byte(0)

type AttestationIma struct {
	DeviceID 	uuid.UUID
	Attestation *attest.Attestation
	Ima         []string
}

type Measurement struct {
	PcrBank      int
	TemplateHash []byte
	Template     string
	FileHashSha1 []byte
	FileName     string
}

type MeasurementNg struct {
	PcrBank      int
	TemplateHash []byte
	Template     string
	HashAlgo     string
	FileHash     []byte
	FileName     string
}

type MeasurementSig struct {
	PcrBank      int
	TemplateHash []byte
	Template     string
	HashAlgo     string
	FileHash     []byte
	FileName     string
	Signature    *Signature // Optional Signature
}

type MeasurementBuf struct {
	PcrBank      int
	TemplateHash []byte
	Template     string
	HashAlgo     string
	FileHash     []byte
	FileName     string
	data         *Buffer
}

type ImaRecord struct {
	ID  string
	Ima []map[string]string
}

type RefID struct {
	Id         string
	References comid.ReferenceValue
}

// Named Information Hash Algorithm Registry
// https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg
func HashIdToString(id uint64) string {
	var hashString string
	switch id {
	case 1:
		hashString = "sha256"
	case 2:
		hashString = "sha256-128"
	case 3:
		hashString = "sha256-120"
	case 4:
		hashString = "sha256-96"
	case 5:
		hashString = "sha256-64"
	case 6:
		hashString = "sha256-32"
	case 7:
		hashString = "sha384"
	case 8:
		hashString = "sha512"
	case 9:
		hashString = "sha3-224"
	case 10:
		hashString = "sha3-256"
	case 11:
		hashString = "sha3-382"
	case 12:
		hashString = "sha3-512"
	default:
		hashString = ""
	}
	return hashString
}

func CheckIma(structuredMeasurements interface{}, fileHash string, filePath string, myPcr10 []byte) (bool, []byte) {
	decodedFileHash, err := hex.DecodeString(string(structuredMeasurements.(Measurement).FileHashSha1))
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHash, err := PackIMAHash("sha1", decodedFileHash)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	packedFilePath, err := PackIMAPath([]byte(structuredMeasurements.(Measurement).FileName))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntry := append(packedFileHash, packedFilePath...)
	shaHash := sha1.Sum(packedTemplateEntry)

	sha256Hash := sha256.New()
	sha256Hash.Write(packedTemplateEntry)
	final256Hash := sha256Hash.Sum(nil)

	decodedFileHashStored, err := hex.DecodeString(fileHash)
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHashStored, err := PackIMAHash("sha1", decodedFileHashStored)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	packedFilePathStored, err := PackIMAPath([]byte(filePath))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntryStored := append(packedFileHashStored, packedFilePathStored...)
	shaHashStored := sha1.Sum(packedTemplateEntryStored)

	if !bytes.Equal(shaHash[:], shaHashStored[:]) {
		log.Fatalf("Failed validating integrity of ima file %v", structuredMeasurements.(Measurement).FileName)
		return false, nil
	}

	extendedHash, err := ExtendIMAEntries(myPcr10, [32]byte(final256Hash))
	if err != nil {
		log.Fatalf("Error computing hash: %v\n", err)
	}
	myPcr10 = extendedHash

	return true, myPcr10
}

func CheckImaNg(structuredMeasurements interface{}, fileHash string, filePath string, myPcr10 []byte) (bool, []byte) {
	decodedFileHash, err := hex.DecodeString(string(structuredMeasurements.(MeasurementNg).FileHash))
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHash, err := PackIMAHash(structuredMeasurements.(MeasurementNg).HashAlgo, decodedFileHash)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	packedFilePath, err := PackIMAPath([]byte(structuredMeasurements.(MeasurementNg).FileName))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntry := append(packedFileHash, packedFilePath...)
	shaHash := sha1.Sum(packedTemplateEntry)

	sha256Hash := sha256.New()
	sha256Hash.Write(packedTemplateEntry)
	final256Hash := sha256Hash.Sum(nil)

	fileHashsh := strings.Split(fileHash, ":")
	decodedFileHashStored, err := hex.DecodeString(fileHashsh[1])
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHashStored, err := PackIMAHash(fileHashsh[0], decodedFileHashStored)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	packedFilePathStored, err := PackIMAPath([]byte(filePath))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntryStored := append(packedFileHashStored, packedFilePathStored...)
	shaHashStored := sha1.Sum(packedTemplateEntryStored)
	//fmt.Println(filePath, hex.EncodeToString(shaHashStored[:]))
	//fmt.Println(structuredMeasurements.(MeasurementNg).FileName, hex.EncodeToString(shaHash[:]), "\n")
	if !bytes.Equal(shaHash[:], shaHashStored[:]) {
		log.Fatalf("Failed validating integrity of ima file %v ", structuredMeasurements.(MeasurementNg).FileName)
	}
	extendedHash, err := ExtendIMAEntries(myPcr10, [32]byte(final256Hash))
	if err != nil {
		log.Fatalf("Error computing hash: %v\n", err)
	}
	myPcr10 = extendedHash

	return true, myPcr10
}

func CheckImaSig(structuredMeasurements interface{}, fileHash string, filePath string, myPcr10 []byte) (bool, []byte) {
	decodedFileHash, err := hex.DecodeString(string(structuredMeasurements.(MeasurementSig).FileHash))
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHash, err := PackIMAHash(structuredMeasurements.(MeasurementSig).HashAlgo, decodedFileHash)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	packedFilePath, err := PackIMAPath([]byte(structuredMeasurements.(MeasurementSig).FileName))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntry := append(packedFileHash, packedFilePath...)
	shaHash := sha1.Sum(packedTemplateEntry)

	sha256Hash := sha256.New()
	sha256Hash.Write(packedTemplateEntry)
	final256Hash := sha256Hash.Sum(nil)

	fileHashsh := strings.Split(fileHash, ":")
	decodedFileHashStored, err := hex.DecodeString(fileHashsh[1])
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHashStored, err := PackIMAHash(fileHashsh[0], decodedFileHashStored)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	filePathth := strings.Split(filePath, " ")
	packedFilePathStored, err := PackIMAPath([]byte(filePathth[0]))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntryStored := append(packedFileHashStored, packedFilePathStored...)
	shaHashStored := sha1.Sum(packedTemplateEntryStored)

	if !bytes.Equal(shaHash[:], shaHashStored[:]) {
		log.Fatalf("Failed validating integrity of ima file %v", structuredMeasurements.(MeasurementNg).FileName)
	}
	extendedHash, err := ExtendIMAEntries(myPcr10, [32]byte(final256Hash))
	if err != nil {
		log.Fatalf("Error computing hash: %v\n", err)
	}
	myPcr10 = extendedHash

	return true, myPcr10
}

func CheckImaBuf(structuredMeasurements interface{}, fileHash string, filePath string, myPcr10 []byte) (bool, []byte) {
	decodedFileHash, err := hex.DecodeString(string(structuredMeasurements.(MeasurementBuf).FileHash))
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHash, err := PackIMAHash(structuredMeasurements.(MeasurementBuf).HashAlgo, decodedFileHash)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	packedFilePath, err := PackIMAPath([]byte(structuredMeasurements.(MeasurementBuf).FileName))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntry := append(packedFileHash, packedFilePath...)
	shaHash := sha1.Sum(packedTemplateEntry)

	sha256Hash := sha256.New()
	sha256Hash.Write(packedTemplateEntry)
	final256Hash := sha256Hash.Sum(nil)

	fileHashsh := strings.Split(fileHash, ":")
	decodedFileHashStored, err := hex.DecodeString(fileHashsh[1])
	if err != nil {
		log.Fatalf("Failed to decode 'file hash' field")
		return false, nil
	}
	packedFileHashStored, err := PackIMAHash(fileHashsh[0], decodedFileHashStored)
	if err != nil {
		log.Fatalf("Failed to pack 'file hash' field")
		return false, nil
	}
	filePathth := strings.Split(filePath, " ")
	packedFilePathStored, err := PackIMAPath([]byte(filePathth[0]))
	if err != nil {
		log.Fatalf("Failed to pack 'file path' field")
		return false, nil
	}

	packedTemplateEntryStored := append(packedFileHashStored, packedFilePathStored...)
	shaHashStored := sha1.Sum(packedTemplateEntryStored)

	if !bytes.Equal(shaHash[:], shaHashStored[:]) {
		log.Fatalf("Failed validating integrity of ima file %v", structuredMeasurements.(MeasurementNg).FileName)
	}
	extendedHash, err := ExtendIMAEntries(myPcr10, [32]byte(final256Hash))
	if err != nil {
		log.Fatalf("Error computing hash: %v\n", err)
	}
	myPcr10 = extendedHash

	return true, myPcr10
}

func ReadMeasurements(measurements []string) []interface{} {

	var structuredMeasurements []interface{}

	for i := 0; i < len(measurements); i++ {

		measurement := strings.Split(measurements[i], " ")
		template := measurement[2]

		switch template {
		case "ima":
			pcrBank, err := strconv.Atoi(measurement[0])
			if err != nil {
				log.Fatalf("Error encoding pcr bank: %v", err)
			}
			templateHash := measurement[1]
			if len(templateHash) != 40 {
				log.Fatalf("Error template hash size")
				return nil
			}
			fileHashSha1 := measurement[3]
			if len(fileHashSha1) != 40 {
				log.Fatalf("Error file hash size")
				return nil
			}
			fileName := measurement[4]
			if len(fileName) > 255 {
				path := strings.Split(fileName, "/")
				fileName = path[len(path[:])-1]
			}
			newMeasurement := Measurement{PcrBank: pcrBank, TemplateHash: []byte(templateHash), Template: template, FileHashSha1: []byte(fileHashSha1), FileName: fileName}
			structuredMeasurements = append(structuredMeasurements, newMeasurement)

		case "ima-ng":
			pcrBank, err := strconv.Atoi(measurement[0])
			if err != nil {
				log.Fatalf("Error encoding pcr bank: %v", err)
			}
			templateHash := measurement[1]
			algo := measurement[3]
			fileHash := measurement[4]
			fileName := measurement[5]
			newMeasurement := MeasurementNg{PcrBank: pcrBank, TemplateHash: []byte(templateHash), Template: template, HashAlgo: algo, FileHash: []byte(fileHash), FileName: fileName}
			structuredMeasurements = append(structuredMeasurements, newMeasurement)

		case "ima-sig":
			pcrBank, err := strconv.Atoi(measurement[0])
			if err != nil {
				log.Fatalf("Error encoding pcr bank: %v", err)
			}
			templateHash := measurement[1]
			algo := measurement[3]
			fileHash := measurement[4]
			fileName := measurement[5]
			var signature *Signature
			if len(measurement) == 7 {
				signature, err = NewSignature(measurement[6])
				if err != nil {
					log.Fatalf("Error signature length: %v", err)
					return nil
				}
			}
			newMeasurement := MeasurementSig{PcrBank: pcrBank, TemplateHash: []byte(templateHash), Template: template, HashAlgo: algo, FileHash: []byte(fileHash), FileName: fileName, Signature: signature}
			structuredMeasurements = append(structuredMeasurements, newMeasurement)

		case "ima-buf":
			pcrBank, err := strconv.Atoi(measurement[0])
			if err != nil {
				log.Fatalf("Error encoding pcr bank: %v", err)
			}
			templateHash := measurement[1]
			algo := measurement[3]
			fileHash := measurement[4]
			fileName := measurement[5]
			buffer, err := NewBuffer(measurement[6])
			if err != nil {
				log.Fatalf("Error buffer data: %v", err)
				return nil
			}
			newMeasurement := MeasurementBuf{PcrBank: pcrBank, TemplateHash: []byte(templateHash), Template: template, HashAlgo: algo, FileHash: []byte(fileHash), FileName: fileName, data: buffer}
			structuredMeasurements = append(structuredMeasurements, newMeasurement)
		}
	}
	return structuredMeasurements
}

// Function to pack IMA hash
func PackIMAHash(hashAlg string, fileHash []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack total length (algorithm + 2 extra bytes + hash length)
	totalLen := uint32(len(hashAlg) + 2 + len(fileHash))
	if err := binary.Write(buf, binary.LittleEndian, totalLen); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %v", err)
	}

	// Pack algorithm
	if _, err := buf.Write([]byte(hashAlg)); err != nil {
		return nil, fmt.Errorf("failed to pack algorithm: %v", err)
	}

	// Pack COLON_BYTE (1 byte)
	if err := buf.WriteByte(COLON_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack COLON_BYTE: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := buf.WriteByte(NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}

	// Pack fileHash (len(fileHash) bytes)
	if _, err := buf.Write(fileHash); err != nil {
		return nil, fmt.Errorf("failed to pack fileHash: %v", err)
	}

	return buf.Bytes(), nil
}

// Function to pack IMA path (similar to pack_ima_path in Python)
func PackIMAPath(path []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack length (4 bytes)
	length := uint32(len(path) + 1) // length + 1 for NULL_BYTE
	if err := binary.Write(buf, binary.LittleEndian, length); err != nil {
		return nil, fmt.Errorf("failed to pack length: %v", err)
	}

	// Pack path (len(path) bytes)
	if _, err := buf.Write(path); err != nil {
		return nil, fmt.Errorf("failed to pack path: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := binary.Write(buf, binary.LittleEndian, NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}
	return buf.Bytes(), nil
}

func ExtendIMAEntries(previousHash []byte, templateHashBytes [32]byte) ([]byte, error) {
	// Create a new SHA context
	hash := sha256.New()

	// Concatenate previous hash and the new template hash
	dataToHash := append(previousHash, templateHashBytes[:]...)

	// Compute the new hash
	hash.Write(dataToHash)
	return hash.Sum(nil), nil
}

// ParserError is a custom error type for invalid signature errors
type ParserError struct {
	Message string
}

func (e *ParserError) Error() string {
	return e.Message
}

// HexData represents the base type that holds raw hexadecimal data
type HexData struct {
	data []byte
}

// NewHexData creates a new HexData object from a hexadecimal string
func NewHexData(data string) (*HexData, error) {
	// Convert the hex string to a byte slice
	decodedData, err := hex.DecodeString(data)
	if err != nil {
		return nil, &ParserError{Message: fmt.Sprintf("Provided data was not valid hex: %s", data)}
	}
	return &HexData{data: decodedData}, nil
}

// String returns the UTF-8 string representation of the HexData
func (hd *HexData) String() string {
	return string(hd.data)
}

// Struct serializes the HexData into a byte slice with length prepended
func (hd *HexData) Struct() ([]byte, error) {
	// Pack the length of the data and the data itself
	length := uint32(len(hd.data))
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, length); err != nil {
		return nil, err
	}
	buf.Write(hd.data)
	return buf.Bytes(), nil
}

type Buffer struct {
	HexData
}

// NewBuffer creates a new Buffer object from a hexadecimal string
func NewBuffer(data string) (*Buffer, error) {
	// Create a HexData object
	hexData, err := NewHexData(data)
	if err != nil {
		return nil, err
	}

	// Initialize the Buffer object with the decoded data
	buf := &Buffer{HexData: *hexData}

	// Return the valid Buffer object
	return buf, nil
}

// Signature represents the "sig" type and inherits HexData
type Signature struct {
	HexData
}

// NewSignature creates a new Signature object from a hexadecimal string
func NewSignature(data string) (*Signature, error) {
	// Create a HexData object
	hexData, err := NewHexData(data)
	if err != nil {
		return nil, err
	}

	// Initialize the Signature object with the decoded data
	sig := &Signature{HexData: *hexData}

	// Perform basic checks on the signature
	// The struct format is ">BBBIH", which corresponds to:
	//   >  : big-endian
	//   B  : byte (1 byte)
	//   I  : unsigned int (4 bytes)
	//   H  : unsigned short (2 bytes)
	const hdrlen = 12 // >BBBIH corresponds to 1 + 1 + 4 + 2 = 12 bytes

	// Ensure the data is large enough to contain the header
	if len(sig.data) < hdrlen {
		return nil, &ParserError{Message: "Invalid signature: header too short"}
	}

	// Unpack the header using binary.Read
	var sigSize uint16
	buf := bytes.NewReader(sig.data[:hdrlen])
	err = binary.Read(buf, binary.BigEndian, &sigSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack signature header: %v", err)
	}

	// Ensure the total length matches the header size + signature size
	if hdrlen+int(sigSize) != len(sig.data) {
		return nil, &ParserError{
			Message: fmt.Sprintf("Invalid signature: malformed header (%d + %d != %d)", hdrlen, sigSize, len(sig.data)),
		}
	}

	// Return the valid Signature object
	return sig, nil
}
