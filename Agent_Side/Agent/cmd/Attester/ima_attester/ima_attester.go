package ima_attester

import (
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/uuid"
)

const ImaFile = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"

type AttestationIma struct {
	DeviceID    uuid.UUID
	Attestation *attest.Attestation
	Ima         []string
}

// reads Ima file, returns NULL measurement on failure
func ReadIma(imaPath string) []string {
	f, err := os.Open(imaPath)
	if err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}
	defer f.Close()

	var measurements []string
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {

		line := scanner.Text()
		fields := strings.Fields(line)
		pcrBank := fields[0]
		templateHash := []byte(fields[1])
		template := fields[2]

		switch template {
		case "ima":
			fileHashSha1 := fields[3]
			fileName := fields[4]
			newMeasurement := pcrBank + " " + string(templateHash[:]) + " " + template + " " + fileHashSha1 + " " + fileName
			measurements = append(measurements, newMeasurement)

		case "ima-ng":
			algocheck := strings.Split(fields[3], ":")
			if len(algocheck) < 2 {
				log.Fatalf("Error reading IMA file, algohash array is too short")
			}
			algo := algocheck[0]
			fileHash := []byte(algocheck[1])
			fileName := fields[4]
			newMeasurement := pcrBank + " " + string(templateHash[:]) + " " + template + " " + algo + " " + string(fileHash[:]) + " " + fileName
			measurements = append(measurements, newMeasurement)

		case "ima-sig":
			algocheck := strings.Split(fields[3], ":")
			if len(algocheck) < 2 {
				log.Fatalf("Error reading IMA file, algohash array is too short")
			}
			algo := algocheck[0]
			fileHash := []byte(algocheck[1])
			fileName := fields[4]
			signature := []byte(fields[5])
			newMeasurement := pcrBank + " " + string(templateHash[:]) + " " + template + " " + algo + " " + string(fileHash[:]) + " " + fileName + " " + string(signature[:])
			measurements = append(measurements, newMeasurement)

		case "ima-buf":
			algocheck := strings.Split(fields[3], ":")
			if len(algocheck) < 2 {
				log.Fatalf("Error reading IMA file, algohash array is too short")
			}
			algo := algocheck[0]
			fileHash := []byte(algocheck[1])
			fileName := fields[4]
			buffer := []byte(fields[5])
			newMeasurement := pcrBank + " " + string(templateHash[:]) + " " + template + " " + algo + " " + string(fileHash[:]) + " " + fileName + " " + string(buffer[:])
			measurements = append(measurements, newMeasurement)
		}

	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading ima %v", err)
		return []string{}
	}
	return measurements
}
