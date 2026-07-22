package attester

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	c "config"
	"ima_attester"
	u "utils_attester"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

var (
	tpmPathth = flag.String("tpm-pathth", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket)")
)
var server *http.Server

func Attest(verbose bool) int {

	rwc, err := tpm2.OpenTPM(*tpmPathth)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer rwc.Close()

	configuration := ReadConf()

	if !configuration.WaitVerifier.Wait {
		ak, err := client.LoadCachedKey(rwc, tpmutil.Handle(0x81000001), client.NullSession{})
		if err != nil {
			log.Fatalf("loading cached key: %v", err)
		}
		defer ak.Close()

		var nonce []byte
		if verbose {
			log.Println("Trying to contact the Verifier...")
		}

		idEncoded, err := tpm2.NVReadEx(rwc, tpmutil.Handle(0x1000001), tpm2.HandleOwner, "", 0)
		if err != nil {
			log.Fatalf("failed reading id %v", err)
		}

		id, err := uuid.Parse(string(idEncoded))
		if err != nil {
			log.Fatalf("failed receiving id %v", err)
		}

		if verbose {
			log.Println("ID sent to the verifier:", id)
		}

		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(id)
		if err != nil {
			log.Fatalf("failed encode id %v", err)
		}
		url := fmt.Sprintf("http://%s:%d/nonce",
			configuration.VerifierNet.Ip, configuration.VerifierNet.Port)
		resp, err := http.Post(url, "application/json", b)
		if err != nil {
			log.Fatalf("failed send id %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			log.Fatalf("failed receiving nonce %v", err)
		}

		nonce, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed receiving nonce %v", err)
		}
		if verbose {
			log.Println("Received nonce:", base64.StdEncoding.EncodeToString(nonce))
		}

		idEncoded, err = tpm2.NVReadEx(rwc, tpmutil.Handle(0x1000001), tpm2.HandleOwner, "", 0)
		if err != nil {
			log.Fatalf("failed reading id %v", err)
		}

		id, err = uuid.Parse(string(idEncoded))
		if err != nil {
			log.Fatalf("failed receiving id %v", err)
		}

		attestation, err := u.Attest(client.AttestOpts{Nonce: nonce}, rwc, ak)
		if err != nil {
			log.Fatalf("failed to create attestation: %v", err)
		}
		if verbose {
			log.Println("Attestation Created...")
		}

		measurements := ima_attester.ReadIma(ima_attester.ImaFile)

		attestationIma := ima_attester.AttestationIma{DeviceID: id, Attestation: attestation, Ima: measurements}

		b = new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(attestationIma)
		if err != nil {
			log.Fatalf("failed encode Attestation data %v", err)
		}
		url = fmt.Sprintf("http://%s:%d/verifyattestation",
			configuration.VerifierNet.Ip, configuration.VerifierNet.Port)
		resp, err = http.Post(url, "application/json", b)
		if err != nil {
			log.Fatalf("failed send Attestation data %v", err)
		}
		defer resp.Body.Close()
		if verbose {
			log.Println("Attestation Sent!")
		}

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("failed to verify Attestation data: %v", err)
		}
	} else {
		http.HandleFunc("/startattest", func(w http.ResponseWriter, r *http.Request) {
			//log.Println("WAITING FOR THE VERIFIER...")

			if r.Method == http.MethodGet {

				// Respond with OK status
				w.WriteHeader(http.StatusOK) // Set status code to 200 OK
				fmt.Fprintf(w, "Server available!")

			} else if r.Method == http.MethodPost {

				ak, err := client.LoadCachedKey(rwc, tpmutil.Handle(0x81000001), client.NullSession{})
				if err != nil {
					log.Fatalf("loading cached key: %v", err)
				}
				defer ak.Close()

				var nonce []byte

				if verbose {
					log.Println("Waiting for the Verifier...")
				}

				err = json.NewDecoder(r.Body).Decode(&nonce)

				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				//w.WriteHeader(http.StatusOK)
				//w.Write([]byte("ATTESTATION STARTED!"))

				idEncoded, err := tpm2.NVReadEx(rwc, tpmutil.Handle(0x1000001), tpm2.HandleOwner, "", 0)
				if err != nil {
					log.Fatalf("failed reading id %v", err)
				}

				id, err := uuid.Parse(string(idEncoded))
				if err != nil {
					log.Fatalf("failed receiving id %v", err)
				}

				attestation, err := u.Attest(client.AttestOpts{Nonce: nonce}, rwc, ak)
				if err != nil {
					log.Fatalf("failed to create attestation: %v", err)
				}
				if verbose {
					log.Println("Attestation Created...")
				}

				measurements := ima_attester.ReadIma(ima_attester.ImaFile)

				attestationIma := ima_attester.AttestationIma{DeviceID: id, Attestation: attestation, Ima: measurements}

				b := new(bytes.Buffer)
				err = json.NewEncoder(b).Encode(attestationIma)
				if err != nil {
					log.Fatalf("failed encode Attestation data %v", err)
				}
				url := fmt.Sprintf("http://%s:%d/verifyattestation", configuration.VerifierNet.Ip, configuration.VerifierNet.Port)
				_, err = http.Post(url, "application/json", b)
				if err != nil {
					log.Fatalf("failed send Attestation data %v", err)
				}
			}
		})

		http.HandleFunc("/endattest", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var confirmation string
			err = json.NewDecoder(r.Body).Decode(&confirmation)

			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if confirmation == "Attestation Ended" {
				log.Println("Attester module run properly")
			}

		})

		server = &http.Server{Addr: configuration.AgentNet.Ip + ":" + strconv.Itoa(configuration.AgentNet.AttesterPort)}
		/*url := fmt.Sprintf("%s:%d",
		configuration.AgentNet.Ip, configuration.AgentNet.AttesterPort)*/

		/*if err := http.ListenAndServe(url, nil); err != http.ErrServerClosed {
			panic(err)
		}*/
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed && err != http.ErrAbortHandler {
			panic(err)
		}
	}

	return 0
}

func ReadConf() c.Configurations {
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath("./config")

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yml")
	var configuration c.Configurations

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}

	err := viper.Unmarshal(&configuration)
	if err != nil {
		fmt.Printf("Unable to decode into struct, %v", err)
	}
	return configuration
}
