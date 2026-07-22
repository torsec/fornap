package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/veraison/corim/comid"
	"github.com/veraison/swid"
)

const imaFile = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"

type Ext struct {
	FileName string `json:"filename,omitempty"`
}

func main() {

	var Reference comid.ReferenceValue

	ima := ReadReference()
	var extension Ext
	for i := 0; i < len(ima); i++ {

		fileHash := strings.Split(ima[i]["fileHash"], ":")
		hash := fileHash[0]
		val := fileHash[1]
		var m comid.Measurement

		switch hash {
		case "sha256":
			decodedHash, err := hex.DecodeString(val)
			if err != nil {
				log.Fatalf("%v", err)
			}
			m.AddDigest(swid.Sha256, decodedHash)
		}

		extension.FileName = ima[i]["file"]
		extension2 := extension
		m.Val.RegisterExtensions(&extension2)
		Reference.Measurements.AddMeasurement(&m)
		//filename := Reference.Measurements[i].Val.Extensions.IExtensionsValue
		//fmt.Println(filename)
	}

	b := new(bytes.Buffer)

	err := json.NewEncoder(b).Encode(Reference)
	if err != nil {
		log.Fatalf("failed encode Reference Values %v", err)
	}

	//fmt.Println(b)
	url := "http://192.168.0.122:8080/insertreference"

	resp, err := http.Post(url, "application/json", b)

	if err != nil {
		log.Fatalf("failed send Reference Values %v", err)
	}

	defer resp.Body.Close()

}

type ReferenceMeasurement struct {
	HashAlgo string
	FileHash []byte
	FileName string
	Data     *[]byte
}

func ReadReference() []map[string]string {
	f, err := os.Open(imaFile)
	if err != nil {
		log.Fatalf("Error reading IMA file, %v", err)
	}
	defer f.Close()
	ima := []map[string]string{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		line := scanner.Text()
		fields := strings.Fields(line)

		template := fields[2]

		switch template {
		case "ima":
			fileHashSha1 := fields[3]
			fileName := fields[4]
			newMeasurement := ReferenceMeasurement{
				FileHash: []byte(fileHashSha1),
				FileName: fileName,
			}
			imaMeasurement := map[string]string{"fileHash": string(newMeasurement.FileHash), "file": newMeasurement.FileName}
			ima = append(ima, imaMeasurement)

		case "ima-ng":
			algocheck := strings.Split(fields[3], ":")
			if len(algocheck) < 2 {
				log.Fatalf("Error reading IMA file, algohash array is too short")
			}
			algo := algocheck[0]
			fileHash := []byte(algocheck[1])
			fileName := fields[4]
			newMeasurement := ReferenceMeasurement{
				HashAlgo: algo,
				FileHash: fileHash,
				FileName: fileName,
			}
			imaMeasurement := map[string]string{"fileHash": newMeasurement.HashAlgo + ":" + string(newMeasurement.FileHash), "file": newMeasurement.FileName}
			ima = append(ima, imaMeasurement)

		case "ima-sig":
			algocheck := strings.Split(fields[3], ":")
			if len(algocheck) < 2 {
				log.Fatalf("Error reading IMA file, algohash array is too short")
			}
			algo := algocheck[0]
			fileHash := []byte(algocheck[1])
			fileName := fields[4]
			signature := []byte(fields[5])
			newMeasurement := ReferenceMeasurement{
				HashAlgo: algo,
				FileHash: fileHash,
				FileName: fileName,
				Data:     &signature,
			}
			imaMeasurement := map[string]string{"fileHash": newMeasurement.HashAlgo + ":" + string(newMeasurement.FileHash), "file": newMeasurement.FileName + " " + string(*newMeasurement.Data)}
			ima = append(ima, imaMeasurement)

		case "ima-buf":
			algocheck := strings.Split(fields[3], ":")
			if len(algocheck) < 2 {
				log.Fatalf("Error reading IMA file, algohash array is too short")
			}
			algo := algocheck[0]
			fileHash := []byte(algocheck[1])
			fileName := fields[4]
			buffer := []byte(fields[5])
			newMeasurement := ReferenceMeasurement{
				HashAlgo: algo,
				FileHash: fileHash,
				FileName: fileName,
				Data:     &buffer,
			}
			imaMeasurement := map[string]string{"fileHash": newMeasurement.HashAlgo + ":" + string(newMeasurement.FileHash), "file": newMeasurement.FileName + " " + string(*newMeasurement.Data)}
			ima = append(ima, imaMeasurement)

		}

	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return nil
	}

	return ima
}
