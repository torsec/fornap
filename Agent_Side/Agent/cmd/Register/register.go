package register

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	c "config"
	t "templates"

	u "utils_register"

	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket)")
	/*ekTest  = `-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhIVjeL1ZyJfjrP8AuIAp
	6OgdvEM5PKV15Q9jA1XFT2s4S5aX0S8H5yf/95xY95VeOPWupg/BnO0IM85GMdr3
	cmdb7Pvlusqa16QLU7xH2KLygDIQebC++DEd3yg4uocF9O+h2fbWkTqDFt5kIRNT
	oVympUwcklAGk2hxfuc5f/ZColbXQyRQ35vwSh0S/vEnl0VXsHqQb1SjA/WGqBKe
	AbiA6ubfAB9dESxTSd70phNJnBdZvokSsgzQ6pj/VS/h82Z3kFBQnBdArhYp9CVP
	n753agkeliQX30IcziX8mVKDX5qlnzRwZ80D2eG6T8Tz2WtzswwhO5UwKKPgy71e
	owIDAQAB
	-----END PUBLIC KEY-----`
		ekCertTest = `-----BEGIN CERTIFICATE-----
	MIIElTCCA32gAwIBAgIEFMzNOTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC
	REUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwR
	T1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkg
	UlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMB4XDTE2MDEwMTEzMTAyMloXDTMxMDEw
	MTEzMTAyMlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAISFY3i9
	WciX46z/ALiAKejoHbxDOTyldeUPYwNVxU9rOEuWl9EvB+cn//ecWPeVXjj1rqYP
	wZztCDPORjHa93JnW+z75brKmtekC1O8R9ii8oAyEHmwvvgxHd8oOLqHBfTvodn2
	1pE6gxbeZCETU6FcpqVMHJJQBpNocX7nOX/2QqJW10MkUN+b8EodEv7xJ5dFV7B6
	kG9UowP1hqgSngG4gOrm3wAfXREsU0ne9KYTSZwXWb6JErIM0OqY/1Uv4fNmd5BQ
	UJwXQK4WKfQlT5++d2oJHpYkF99CHM4l/JlSg1+apZ80cGfNA9nhuk/E89lrc7MM
	ITuVMCij4Mu9XqMCAwEAAaOCAZEwggGNMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEF
	BQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDMv
	T3B0aWdhUnNhTWZyQ0EwMDMuY3J0MA4GA1UdDwEB/wQEAwIAIDBRBgNVHREBAf8E
	RzBFpEMwQTEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDETMBEGBWeBBQICDAhTTEIg
	OTY2NTESMBAGBWeBBQIDDAdpZDowNTI4MAwGA1UdEwEB/wQCMAAwUAYDVR0fBEkw
	RzBFoEOgQYY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0Ew
	MDMvT3B0aWdhUnNhTWZyQ0EwMDMuY3JsMBUGA1UdIAQOMAwwCgYIKoIUAEQBFAEw
	HwYDVR0jBBgwFoAUQLhoK40YRQorBoSdm1zZb0zd9L4wEAYDVR0lBAkwBwYFZ4EF
	CAEwIQYDVR0JBBowGDAWBgVngQUCEDENMAsMAzIuMAIBAAIBdDANBgkqhkiG9w0B
	AQsFAAOCAQEApynlEZGc4caT7bQJjhrvOtv4RFu3FNA9hgsF+2BGltsumqo9n3nU
	GoGt65A5mJAMCY1gGF1knvUFq8ey+UuIFw3QulHGENOiRu0aT3x9W7c6BxQIDFFC
	PtA+Qvvg+HJJ6XjihQRc3DU01HZm3xD//fGIDuYasZwBd2g/Ejedp2tKBl2M98FO
	48mbZ4WtaPrEALn3UQMf27pWqe2hUKFSKDEurijnchsdmRjTmUEWM1/9GFkh6IrT
	YvRBngNqOffJ+If+PI3x2GXkGnzsA6IxroEY9CwOhmNp+6xbAgqUedd5fWMLBN3Q
	MjHSp1Sl8wp00xRztfh0diBdicy3Hbn03g==
	-----END CERTIFICATE-----`*/
)

var server *http.Server
var done = make(chan bool)

func Register(print bool, verbose bool) int {

	var cmds [4]*exec.Cmd
	cmds[0] = exec.Command("sudo", "tpm2_flushcontext", "-l")
	cmds[1] = exec.Command("sudo", "tpm2_flushcontext", "-s")
	cmds[2] = exec.Command("sudo", "tpm2_flushcontext", "-t")
	cmds[3] = exec.Command("sudo", "tpm2_clear")
	for i := 0; i < len(cmds); i++ {
		// Execute the command and capture any output or errors
		_, err := cmds[i].CombinedOutput()

		// Check if there was an error executing the command
		if err != nil {
			log.Fatalf("Error executing command: %v\n", err)
		}
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer rwc.Close()

	configuration := ReadConf()
	var nonce []byte

	if !configuration.WaitRegister.Wait {

		if verbose {
			log.Println("Trying to contact the Register...")
		}

		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode("Hi! I'm a new Device, I'd like to register.")
		if err != nil {
			log.Fatalf("failed to encode request probe: %v", err)
		}

		url := fmt.Sprintf("http://%s:%d/nonce",
			configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
		resp, err := http.Post(url, "application/json", b)
		if err != nil {
			log.Fatalf("failed to send request probe: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			log.Fatalf("failed receiving nonce %v", err)
		}
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed receiving nonce %v", err)
		}
		nonce = respBody
		if verbose {
			log.Println("Received nonce:", base64.StdEncoding.EncodeToString(nonce))
		}

		EKTemplate, SRKTemplate, AKTemplate := ChooseTemplates(configuration)

		//ENDORSEMENT KEY CREATION
		ek, pubEK, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, "", "", EKTemplate)
		if err != nil {
			log.Fatalf("creating ek: %v", err)
		}

		if print {
			fmt.Println("\tENDORSEMENT KEY")
			PrintPubKey(pubEK)
		}

		ekTPMPub, _, _, err := tpm2.ReadPublic(rwc, ek)
		if err != nil {
			log.Fatalf("read ek public: %v", err)
		}

		var EK *client.Key
		if configuration.KeyTemplates.EKTemplate == "RSADefaultEKTemplate" {
			EK, err = client.EndorsementKeyRSA(rwc)
			if err != nil {
				log.Fatalf("ERROR: could not get EndorsementKeyRSA: %v", err)
			}
		}

		if configuration.KeyTemplates.EKTemplate == "ECCDefaultEKTemplate" {
			EK, err = client.EndorsementKeyRSA(rwc)
			if err != nil {
				log.Fatalf("ERROR: could not get EndorsementKeyECC: %v", err)
			}
		}

		defer EK.Close()

		var pemEKCert []byte
		EKCert := EK.Cert()
		if EKCert != nil {
			pemEKCert = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: EKCert.Raw,
			})
		}

		if pemEKCert == nil {
			pemEKCert = []byte("EK Certificate not provided")
		}

		EKCertPem := string(pemEKCert)
		//fmt.Println(EKCertPem)
		//pemPublicEK := encodePublicKeyToPEM(EK.PublicKey())

		//SRK HIERARCHY CREATION
		srk, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, "", "", SRKTemplate)
		if err != nil {
			log.Fatalf("creating srk: %v", err)
		}

		//AK CREATION (coming from SRK hierarchy)
		privBlob, pubBlob, _, _, _, errAK := tpm2.CreateKey(rwc, srk, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, "", "", AKTemplate)
		if errAK != nil {
			log.Fatalf("creating ak: %v", errAK)
		}
		tpmPub, err := tpm2.DecodePublic(pubBlob)
		if err != nil {
			log.Fatalf("decode public blob: %v", err)
		}
		pubAK, err := tpmPub.Key()
		if err != nil {
			log.Fatalf("decode public key: %v", err)
		}

		if print {
			fmt.Println("\tATTESTATION KEY")
			PrintPubKey(pubAK)
		}

		aik, nameData, err := tpm2.Load(rwc, srk, "", pubBlob, privBlob) //returns tha handle of the aik and the nameData
		if err != nil {
			log.Fatalf("load aik: %v", err)
		}

		ak, err := client.LoadCachedKey(rwc, aik, client.NullSession{})
		if err != nil {
			log.Fatalf("loading cached key: %v", err)
		}
		defer ak.Close()

		var quotes []*pb.Quote

		quoteSha256, err := u.Quote(rwc, ak, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}, nonce)
		if err != nil {
			log.Fatalf("failed creating first quote (sha256): %v", err)
		}
		quotes = append(quotes, quoteSha256)

		quoteSha384, err := u.Quote(rwc, ak, tpm2.PCRSelection{Hash: tpm2.AlgSHA384, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}, nonce)
		if err != nil {
			log.Println("failed creating first quote (sha384): ", err, " sending only sha256")
		} else {
			quotes = append(quotes, quoteSha384)
		}
		quoteSha512, err := u.Quote(rwc, ak, tpm2.PCRSelection{Hash: tpm2.AlgSHA512, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}, nonce)
		if err != nil {
			log.Println("failed creating first quote (sha512): ", err, " sending only sha256 and sha384 (if no other error about sha384 are displayed)")
		} else {
			quotes = append(quotes, quoteSha512)
		}

		fq := FirstQuote{EKCertificate: EKCertPem, Quote: quotes, AKPubBlob: pubBlob, Nonce: nonce, WhitelistID: configuration.WhitelistID.ID}
		b = new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(fq)
		if err != nil {
			log.Fatalf("failed encode Endorsement Key Material data %v", err)
		}
		if verbose {
			log.Println("Sending first quote (PCRs 0-9)...")
		}

		url = fmt.Sprintf("http://%s:%d/firstquote",
			configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
		resp, err = http.Post(url, "application/json", b)
		if err != nil {
			log.Fatalf("failed send EK and EKCert %v", err)
		}
		defer resp.Body.Close()

		//log.Println(resp.StatusCode, "firstquote")
		if resp.StatusCode != http.StatusOK {
			log.Fatal("failed verification of first quote:", resp.StatusCode)
		}

		ekTPMPubEncoded, err := ekTPMPub.Encode()
		if err != nil {
			log.Fatalf("encoding ek %v", err)
		}

		data := Data{PubBlob: pubBlob, NameData: nameData, EKTPMPub: ekTPMPubEncoded}

		b = new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(data)
		if err != nil {
			log.Fatalf("failed encode Endorsement Key Material data %v", err)
		}

		if verbose {
			log.Println("Sending EK material data...")
		}

		url = fmt.Sprintf("http://%s:%d/registration",
			configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
		resp, err = http.Post(url, "application/json", b)
		if err != nil {
			log.Fatalf("failed send Endorsement Key Material data %v", err)
		}
		defer resp.Body.Close()

		//log.Println(resp.StatusCode, "registration")
		if resp.StatusCode != http.StatusAccepted {
			log.Fatalf("failed to register the key %v", err)
		}
		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed receiving challenge %v", err)
		}
		if verbose {
			log.Println("Received challenge...")
		}

		credBlob := respBody[0:70]
		encSecret := respBody[70:]

		if verbose {
			log.Println("Solving the challenge...")
		}

		out := SolveChallenge(rwc, aik, ek, credBlob, encSecret)
		solution := ChallengeSolution{Solution: out, WhitelistID: configuration.WhitelistID.ID}

		b = new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(solution)
		if err != nil {
			log.Fatalf("failed encode challenge solution %v", err)
		}
		url = fmt.Sprintf("http://%s:%d/challenge",
			configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
		req, err := http.NewRequest("POST", url, b)
		if err != nil {
			log.Fatal(err)
		}

		// Add custom headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.168.0.103")
		//req.Header.Set("Connection", "close")
		// Create an HTTP client
		client := &http.Client{Transport: &http.Transport{
			// Force HTTP/1.0
			ForceAttemptHTTP2: false,
		},
		}

		// Send the request
		resp, err = client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		//	log.Println(resp.StatusCode, "challenge")
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("failed to verify the challenge %v", err)
		}
		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed receiving ID %v", err)
		}

		id, err := uuid.Parse(string(respBody))
		if err != nil {
			log.Fatalf("failed parsing ID %v", err)
		}
		//if verbose {
		//	log.Println("Received ID:", id.String())
		//}

		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, aik, tpmutil.Handle(0x81000001))
		if err != nil {
			log.Fatalf("failed to store ak: %v", err)
		}

		err = tpm2.NVDefineSpace(rwc, tpm2.HandleOwner, tpmutil.Handle(0x1000001), "", "", []byte(""), tpm2.NVAttr(tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead), uint16(len(id.String())))
		if err != nil {
			log.Fatalf("failed defining nv index in tpm: %v", err)
		}

		err = tpm2.NVWrite(rwc, tpm2.HandleOwner, tpmutil.Handle(0x1000001), "", []byte(id.String()), 0)
		if err != nil {
			log.Fatalf("failed to store id in the tpm: %v", err)
		}

		//log.Println(id.String())
		err = tpm2.FlushContext(rwc, ek)
		if err != nil {
			log.Fatalf("flushing context: %v", err)
		}
	} else {
		EKTemplate, SRKTemplate, AKTemplate := ChooseTemplates(configuration)
		//ENDORSEMENT KEY CREATION
		ek, pubEK, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, "", "", EKTemplate)
		if err != nil {
			log.Fatalf("creating ek: %v", err)
		}
		ekTPMPub, _, _, err := tpm2.ReadPublic(rwc, ek)
		if err != nil {
			log.Fatalf("read ek public: %v", err)
		}

		var EK *client.Key
		if configuration.KeyTemplates.EKTemplate == "RSADefaultEKTemplate" {
			EK, err = client.EndorsementKeyRSA(rwc)
			if err != nil {
				log.Fatalf("ERROR: could not get EndorsementKeyRSA: %v", err)
			}
		}

		if configuration.KeyTemplates.EKTemplate == "ECCDefaultEKTemplate" {
			EK, err = client.EndorsementKeyRSA(rwc)
			if err != nil {
				log.Fatalf("ERROR: could not get EndorsementKeyECC: %v", err)
			}
		}

		defer EK.Close()

		var pemEKCert []byte
		EKCert := EK.Cert()
		if EKCert != nil {
			pemEKCert = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: EKCert.Raw,
			})
		}

		if pemEKCert == nil {
			pemEKCert = []byte("EK Certificate not provided")
		}

		EKCertPem := string(pemEKCert)
		//fmt.Println(EKCertPem)
		//pemPublicEK := encodePublicKeyToPEM(EK.PublicKey())

		//SRK HIERARCHY CREATION
		srk, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, "", "", SRKTemplate)
		if err != nil {
			log.Fatalf("creating srk: %v", err)
		}

		//AK CREATION (coming from SRK hierarchy)
		privBlob, pubBlob, _, _, _, errAK := tpm2.CreateKey(rwc, srk, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, "", "", AKTemplate)
		if errAK != nil {
			log.Fatalf("creating ak: %v", errAK)
		}
		tpmPub, err := tpm2.DecodePublic(pubBlob)
		if err != nil {
			log.Fatalf("decode public blob: %v", err)
		}
		pubAK, err := tpmPub.Key()
		if err != nil {
			log.Fatalf("decode public key: %v", err)
		}

		if print {
			fmt.Println("\tATTESTATION KEY")
			PrintPubKey(pubAK)
		}

		aik, nameData, err := tpm2.Load(rwc, srk, "", pubBlob, privBlob) //returns tha handle of the aik and the nameData
		if err != nil {
			log.Fatalf("load aik: %v", err)
		}

		http.HandleFunc("/startregister", func(w http.ResponseWriter, r *http.Request) {
			if verbose {
				log.Println("Waiting for the Register...")
			}

			err = json.NewDecoder(r.Body).Decode(&nonce)

			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if print {
				fmt.Println("\tENDORSEMENT KEY")
				PrintPubKey(pubEK)
			}

			ak, err := client.LoadCachedKey(rwc, aik, client.NullSession{})
			if err != nil {
				log.Fatalf("loading cached key: %v", err)
			}
			defer ak.Close()

			var quotes []*pb.Quote

			quoteSha256, err := u.Quote(rwc, ak, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}, nonce)
			if err != nil {
				log.Fatalf("failed creating first quote (sha256): %v", err)
			}
			quotes = append(quotes, quoteSha256)

			fq := FirstQuote{EKCertificate: EKCertPem, Quote: quotes, AKPubBlob: pubBlob, Nonce: nonce, WhitelistID: configuration.WhitelistID.ID}
			b := new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(fq)
			if err != nil {
				log.Fatalf("failed encode Endorsement Key Material data %v", err)
			}
			if verbose {
				log.Println("Sending first quote (PCRs 0-9)...")
			}

			url := fmt.Sprintf("http://%s:%d/firstquote",
				configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
			resp, err := http.Post(url, "application/json", b)
			if err != nil {
				log.Fatalf("failed send EK and EKCert %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				log.Fatalf("failed verification of first quote: %v", err)
			}

			ekTPMPubEncoded, err := ekTPMPub.Encode()
			if err != nil {
				log.Fatalf("encoding ek %v", err)
			}

			data := Data{PubBlob: pubBlob, NameData: nameData, EKTPMPub: ekTPMPubEncoded}

			b = new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(data)
			if err != nil {
				log.Fatalf("failed encode Endorsement Key Material data %v", err)
			}

			if verbose {
				log.Println("Sending EK material data...")
			}

			url = fmt.Sprintf("http://%s:%d/registration",
				configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
			resp, err = http.Post(url, "application/json", b)
			if err != nil {
				log.Fatalf("failed send Endorsement Key Material data %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusAccepted {
				log.Fatalf("failed to register the key %v", err)
			}
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("failed receiving challenge %v", err)
			}
			if verbose {
				log.Println("Received challenge...")
			}

			credBlob := respBody[0:70]
			encSecret := respBody[70:]

			if verbose {
				log.Println("Solving the challenge...")
			}

			out := SolveChallenge(rwc, aik, ek, credBlob, encSecret)
			solution := ChallengeSolution{Solution: out, WhitelistID: configuration.WhitelistID.ID}

			b = new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(solution)
			if err != nil {
				log.Fatalf("failed encode challenge solution %v", err)
			}
			url = fmt.Sprintf("http://%s:%d/challenge",
				configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
			/*resp, err = http.Post(url, "application/json", b)
			if err != nil {
				log.Fatalf("failed send challenge solution %v", err)
			}
			defer resp.Body.Close()*/
			req, err := http.NewRequest("POST", url, b)
			if err != nil {
				log.Fatal(err)
			}

			// Add custom headers
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", "192.168.0.103")

			// Create an HTTP client
			client := &http.Client{}

			// Send the request
			resp, err = client.Do(req)
			if err != nil {
				log.Fatal(err)
			}
			defer resp.Body.Close()

		})

		http.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
			id := ""
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			err := json.NewDecoder(r.Body).Decode(&id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			//fmt.Println("Received ID: ", id)
			err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, aik, tpmutil.Handle(0x81000001))
			if err != nil {
				log.Fatalf("failed to store ak: %v", err)
			}

			err = tpm2.NVDefineSpace(rwc, tpm2.HandleOwner, tpmutil.Handle(0x1000001), "", "", []byte(""), tpm2.NVAttr(tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead), uint16(len(id)))
			if err != nil {
				log.Fatalf("failed defining nv index in tpm: %v", err)
			}

			err = tpm2.NVWrite(rwc, tpm2.HandleOwner, tpmutil.Handle(0x1000001), "", []byte(id), 0)
			if err != nil {
				log.Fatalf("failed to store id in the tpm: %v", err)
			}

			err = tpm2.FlushContext(rwc, ek)
			if err != nil {
				log.Fatalf("flushing context: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				fmt.Printf("Error closing server: %v\n", err)
				return
			}

		})
		server = &http.Server{Addr: configuration.AgentNet.Ip + ":" + strconv.Itoa(configuration.AgentNet.RegisterPort)}
		/*url := fmt.Sprintf("%s:%d",
		configuration.AgentNet.Ip, configuration.AgentNet.RegisterPort)
		*/

		//log.Println("Starting Server...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}

	return 0
}

type Data struct {
	PubBlob  []byte
	NameData []byte
	EKTPMPub []byte
}

type FirstQuote struct {
	EKCertificate string
	Quote         []*pb.Quote
	AKPubBlob     []byte
	Nonce         []byte
	WhitelistID   string
}

type ChallengeSolution struct {
	Solution    []byte
	WhitelistID string
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

func ChooseTemplates(conf c.Configurations) (tpm2.Public, tpm2.Public, tpm2.Public) {
	var EKTemplate tpm2.Public
	var SRKTemplate tpm2.Public
	var AKTemplate tpm2.Public
	EKTemplateString := conf.KeyTemplates.EKTemplate
	SRKTemplateString := conf.KeyTemplates.SRKTemplate
	AKTemplateString := conf.KeyTemplates.AKTemplate

	switch EKTemplateString {
	case "RSADefaultEKTemplate":
		EKTemplate = t.RSADefaultEKTemplate
	case "ECCDefaultEKTemplate":
		EKTemplate = t.ECCDefaultEKTemplate
	}
	switch SRKTemplateString {
	case "RSADefaultSRKTemplate":
		SRKTemplate = t.RSADefaultSRKTemplate
	case "ECCDefaultSRKTemplate":
		SRKTemplate = t.ECCDefaultSRKTemplate
	}
	switch AKTemplateString {
	case "RSASSADefaultAKTemplate":
		AKTemplate = t.RSASSADefaultAKTemplate
	case "RSAPSSDefaultAKTemplate":
		AKTemplate = t.RSAPSSDefaultAKTemplate
	case "ECCDefaultAKTemplate":
		AKTemplate = t.ECCDefaultAKTemplate
	}
	return EKTemplate, SRKTemplate, AKTemplate
}

func PrintPubKey(pub crypto.PublicKey) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("encoding public key: %v", err)
	}
	bEK := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	pem.Encode(os.Stdout, bEK)
}

func SolveChallenge(rwc io.ReadWriter, aik tpmutil.Handle, ek tpmutil.Handle, credBlob []byte, encSecret []byte) []byte {
	session, _, err := tpm2.StartAuthSession(rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("creating auth session: %v", err)
		return nil
	}

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		log.Fatalf("policy secret failed: %v", err)
		return nil
	}

	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	out, err := tpm2.ActivateCredentialUsingAuth(rwc, auths, aik, ek, credBlob[2:], encSecret[2:]) //for both credBlob and encSecret, the first field is
	if err != nil {                                                                                //the size of the TPM2B object, the second is respectively
		log.Fatalf("activate credential: %v", err) //the credential and the secret
		return nil
	}
	return out

}

func encodePublicKeyToPEM(pubKey crypto.PublicKey) string {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY", // Use "PUBLIC KEY" for X.509 encoded keys
		Bytes: pubASN1,
	})
	return string(pubPEM)
}
