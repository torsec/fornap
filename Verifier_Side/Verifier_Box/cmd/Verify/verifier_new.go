package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	h "agent_db_handler"
	c "configV"
	"ima_verifier"
	u "utils_verify"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	e "github.com/veraison/ear"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func Verify(verbose bool) int {
	configuration := ReadConf()
	if verbose {
		log.Println("Verifier Running...")
	}

	nonce := make([]byte, 32)
	id := ""
	var ar *e.AttestationResult
	arBroker := NewCircularBuffer(10)

	if configuration.CreateJWTKeys.Create {
		err := GenerateJWTKey(verbose)
		if err != nil {
			log.Fatalf("Error creating keys for JWT: %v", err)
		}
	}

	http.HandleFunc("/deviceid", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var jsonData map[string]string
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		// Unmarshal the JSON data
		err = json.Unmarshal(body, &jsonData)
		if err != nil {
			http.Error(w, "Error unmarshaling JSON", http.StatusBadRequest)
			return
		}
		deviceID := jsonData["Id"]
		//w.WriteHeader(http.StatusOK)
		//log.Println("ID EXTRACTED")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)

		dataSourceName := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			configuration.PostgresDatabase.DBUser, configuration.PostgresDatabase.DBPassword, configuration.PostgreServer.Ip, configuration.PostgreServer.Port, configuration.PostgresDatabase.DBName)
		// Establish a connection to the PostgreSQL database
		db, err := sql.Open("postgres", dataSourceName)
		if err != nil {
			log.Fatal("Error connecting to the database: ", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatal("Not Connected ", err)
		}

		rawIpPort, err := h.ReadIP_Port(db, deviceID)
		if err != nil {
			log.Fatalf("failed retrieving ip_port %v", err)
		}
		//fmt.Println(rawIpPort)
		ipPort := &AgentNet{}
		ipPort.Ip = strings.Split(rawIpPort, ":")[0]
		ipPort.Port = configuration.StartAttestation.Port
		_, err = rand.Read(nonce)
		if err != nil {
			log.Fatalf("creating secret: %v", err)
		}
		data := nonce
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(data)
		if err != nil {
			log.Fatalf("failed to encode nonce %v", err)
		}
		url := fmt.Sprintf("http://%s:%d/startattest",
			ipPort.Ip, ipPort.Port)

		if configuration.StartAttestation.Start {
			for {
				err := pingAPI(url)
				if err != nil {
					//fmt.Println("Errore:", err)
					//fmt.Println("Riprovo fra 3 secondi...")
					time.Sleep(3 * time.Second) // Aspetta 5 secondi prima di riprovare
				} else {
					//fmt.Println("API disponibile! Connessione riuscita.")
					break // Esce dal ciclo se l'API è disponibile
				}
			}
		}

		_, _ = http.Post(url, "application/json", b)
		return
	})

	http.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		err := json.NewDecoder(r.Body).Decode(&id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if verbose {
			log.Println("ID received!", id, r.RemoteAddr)
			log.Println("Creating nonce...")
		}

		_, err = rand.Read(nonce)
		if err != nil {
			log.Fatalf("creating secret: %v", err)
		}

		w.WriteHeader(http.StatusCreated)
		w.Write(nonce)
		if verbose {
			log.Println("Nonce sent:", base64.StdEncoding.EncodeToString(nonce))
		}
	})

	http.HandleFunc("/verifyattestation", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		attestation := &ima_verifier.AttestationIma{}
		err := json.NewDecoder(r.Body).Decode(attestation)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if verbose {
			log.Println("Got Attestation!", r.RemoteAddr)
		}

		rawAKPub := attestation.Attestation.GetAkPub()

		akPub, err := tpm2.DecodePublic(rawAKPub)
		if err != nil {
			log.Fatalf("failed decode pub key")
		}

		pubKey, err := akPub.Key()
		if err != nil {
			log.Fatalf("failed extract pub key")
		}

		dataSourceName := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			configuration.PostgresDatabase.DBUser, configuration.PostgresDatabase.DBPassword, configuration.PostgreServer.Ip, configuration.PostgreServer.Port, configuration.PostgresDatabase.DBName)
		// Establish a connection to the PostgreSQL database
		db, err := sql.Open("postgres", dataSourceName)
		if err != nil {
			log.Fatal("Error connecting to the database: ", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatal("Not Connected ", err)
		}
		id = attestation.DeviceID.String()
		akDB, err := h.ReadAK(db, string(id))
		if err != nil {
			log.Fatal("Error reading the ak: ", err)
		}
		spkiBlock, _ := pem.Decode([]byte(akDB))

		pubAKDER, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			log.Fatalf("encoding public key: %v", err)
		}
		bAK := &pem.Block{Bytes: pubAKDER}

		if !bytes.Equal(bAK.Bytes, spkiBlock.Bytes) {
			log.Fatalf("stored ak pub is different")
		}
		if verbose {
			log.Println("AK validated! Let's check the attestation...")
		}

		status, err := u.VerifyAttestation(attestation.Attestation, u.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{pubKey}, AllowSHA1: true}) // ASK IF YOU NEED TO USE THIS OR THE ONE FROM THE DB
		if err != nil {
			log.Fatalf("failed to verify the attestation %v", err)
		}
		if status != nil && verbose {
			log.Println("Attestation object verified! Let's check the IMA...")
		}
		imaID, err := h.ReadWhitelistId(db, string(id))
		if err != nil {
			log.Fatal("Error reading the IMA id: ", err)
		}
		measurements := attestation.Ima                                       // measurements that have been read from the received object
		structuredMeasurements := ima_verifier.ReadMeasurements(measurements) // measurements restructured as follows PcrBank, TemplateHash, Template, HashAlgo:FileHash, FileName

		// Connect to Mongo
		//uri := fmt.Sprintf("mongodb+srv://%s:%s@%s",
		//	configuration.Mongodb.MongoUser, configuration.Mongodb.MongoPassword, configuration.Mongodb.MongoURL)
		uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/?timeoutMS=5000", configuration.Mongodb.MongoUser, configuration.Mongodb.MongoPassword, configuration.Mongodb.MongoIP, configuration.Mongodb.MongoPort)
		client, err := mongo.NewClient(options.Client().ApplyURI(uri))
		if err != nil {
			log.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = client.Connect(ctx)
		if err != nil {
			log.Fatal(err)
		}
		defer client.Disconnect(ctx)

		err = client.Ping(ctx, readpref.Primary())
		if err != nil {
			log.Fatal(err)
		}
		referenceDatabase := client.Database("reference_values")
		referencesCollection := referenceDatabase.Collection("references")

		var storedIma ima_verifier.ImaRecord
		raw, err := referencesCollection.FindOne(ctx, bson.M{"id": imaID}).Raw()
		if err != nil {
			log.Fatal(err)
		}
		measurementsArray, err := raw.Lookup("references", "measurements").Array().Elements()
		if err != nil {
			log.Fatal(err)
		}

		for _, elem := range measurementsArray {

			result := make(map[string]string)
			hashAlg := ""

			var doc map[string]interface{}
			if err := bson.Unmarshal(elem.Value().Value, &doc); err != nil {
				fmt.Println("Errore durante la decodifica:", err)
				continue
			}

			val, ok := doc["val"].(map[string]interface{})
			if !ok {
				fmt.Println("Campo 'val' non trovato o formato errato")
				continue
			}

			digests, ok := val["digests"].(bson.A)
			if !ok {
				fmt.Println("Campo 'digests' non trovato o formato errato")
				continue
			}

			for _, digest := range digests {
				digestMap := digest.(map[string]interface{})

				if hashalgIDValue, ok := digestMap["hashalgid"].(int64); ok {
					if hashalgIDValue == 1 {
						hashAlg = ima_verifier.HashIdToString(uint64(hashalgIDValue))
					}
				}
				if hashValue, ok := digestMap["hashvalue"].(primitive.Binary); ok {
					if hashAlg == "sha256" {
						decodedHashValue := hashValue.Data
						result["fileHash"] = hashAlg + ":" + hex.EncodeToString(decodedHashValue)
					}

				}
			}
			if hashAlg == "" {
				log.Fatal("No sha256 measurement, can' proceed with IMA verification.")
			}

			if extensions, ok := doc["val"].(map[string]interface{})["extensions"].(map[string]interface{})["extensions"].(map[string]interface{}); ok {
				if iextensionsValue, ok := extensions["iextensionsvalue"].(map[string]interface{})["filename"].(string); ok {
					result["file"] = iextensionsValue
				}

			}
			storedIma.Ima = append(storedIma.Ima, result)
		}

		myPcr10 := make([]byte, 32)
		check := false

		for i := 0; i < len(structuredMeasurements); i++ {
			measurement := strings.Split(measurements[i], " ")
			template := measurement[2]

			switch template {
			case "ima":
				check, myPcr10 = ima_verifier.CheckIma(structuredMeasurements[i], storedIma.Ima[i]["fileHash"], storedIma.Ima[i]["file"], myPcr10)
				if !check {
					log.Fatalf("Error at index %v", i)
				}

			case "ima-ng":
				//fmt.Println(storedIma.Ima[i]["file"])
				check, myPcr10 = ima_verifier.CheckImaNg(structuredMeasurements[i], storedIma.Ima[i]["fileHash"], storedIma.Ima[i]["file"], myPcr10)
				if !check {
					log.Fatalf("Error at index %v", i)
				}

			case "ima-sig":
				check, myPcr10 = ima_verifier.CheckImaSig(structuredMeasurements[i], storedIma.Ima[i]["fileHash"], storedIma.Ima[i]["file"], myPcr10)
				if !check {
					log.Fatalf("Error at index %v", i)
				}

			case "ima-buf":
				check, myPcr10 = ima_verifier.CheckImaBuf(structuredMeasurements[i], storedIma.Ima[i]["fileHash"], storedIma.Ima[i]["file"], myPcr10)
				if !check {
					log.Fatalf("Error at index %v", i)
				}
			}
		}

		//Verify PCR10 value
		if !bytes.Equal(myPcr10, attestation.Attestation.Quotes[1].Pcrs.Pcrs[10]) {
			log.Fatalf("PCR10 verification %v\n", err)
		}

		if verbose {
			log.Println("ATTESTATION VERIFIED!")
		}
		rawIpPort, err := h.ReadIP_Port(db, string(id))
		if err != nil {
			log.Fatalf("failed retrieving ip_port %v", err)
		}

		ipPort := &AgentNet{}
		ipPort.Ip = strings.Split(rawIpPort, ":")[0]
		ipPort.Port = configuration.StartAttestation.Port

		ar = e.NewAttestationResult(id, configuration.VerifierIdentity.Build, configuration.VerifierIdentity.Developer)
		ar.Submods[id].TrustVector.Configuration = e.ApprovedConfigClaim
		ar.Submods[id].TrustVector.Hardware = e.GenuineHardwareClaim
		ar.Submods[id].TrustVector.InstanceIdentity = e.TrustworthyInstanceClaim
		ar.Submods[id].TrustVector.Executables = e.ApprovedRuntimeClaim
		ar.Submods[id].Status = e.NewTrustTier(e.TrustTierAffirming)
		*ar.IssuedAt = time.Now().Unix()
		arBroker.Push(ar)

		log.Println("Device", id, "attested")
		rawECDSAPrivKey, err := ReadJWTKeyFromFile(configuration.JWTKeyPath.VerifierPath)
		if err != nil {
			log.Fatalf("Error reading keys for JWT: %v", err)
		}
		key, err := jwk.FromRaw(rawECDSAPrivKey)
		if err != nil {
			log.Fatalf("Error importing key for JWT: %v\n", err)
		}
		ar, err := arBroker.ReadFirstMatch(id)
		if err != nil {
			log.Fatalf("Error reading attestation result from pool: %v\n", err)
		}

		buf, err := ar.Sign(jwa.ES256, key)
		if err != nil {
			log.Fatalf("Error signing the attestation result: %v\n", err)
		}
		publicKey, err := key.PublicKey()
		if err != nil {
			log.Fatalf("Error extracting public key: %v\n", err)
		}

		arUpdate := AttestationResultUpdate{DeviceID: id, JWT: buf, JWK: publicKey}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(arUpdate)
		if err != nil {
			log.Fatalf("failed to encode attestation result %v", err)
		}

		url := fmt.Sprintf("http://%s:%d/updatestate", configuration.RegisterNet.Ip, configuration.RegisterNet.Port)
		resp, err := http.Post(url, "application/json", b)
		if err != nil {
			log.Fatalf("failed contact register %v", err)
		}
		defer resp.Body.Close()

		if configuration.StartAttestation.Start == true {
			confirm := "Attestation Ended"
			b := new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(confirm)
			if err != nil {
				log.Fatalf("failed to encode attestation result %v", err)
			}

			url := fmt.Sprintf("http://%s:%d/endattest", ipPort.Ip, ipPort.Port)
			_, err = http.Post(url, "application/json", b)
			if err != nil {
				log.Fatalf("failed contact register %v", err)
			}
			seconds := configuration.AttestationPeriod.Seconds
			duration := time.Duration(seconds) * time.Second
			time.Sleep(duration)

			rawIpPort, err := h.ReadIP_Port(db, string(id))
			if err != nil {
				log.Fatalf("failed retrieving ip_port %v", err)
			}

			ipPort := &AgentNet{}
			ipPort.Ip = strings.Split(rawIpPort, ":")[0]
			ipPort.Port = configuration.StartAttestation.Port

			_, err = rand.Read(nonce)
			if err != nil {
				log.Fatalf("creating secret: %v", err)
			}
			data := nonce
			b = new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(data)
			if err != nil {
				log.Fatalf("failed to encode nonce %v", err)
			}

			url = fmt.Sprintf("http://%s:%d/startattest",
				ipPort.Ip, ipPort.Port)
			_, _ = http.Post(url, "application/json", b)
			return
		}

	})

	http.HandleFunc("/attestationresult", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var jsonData map[string]string
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Unmarshal the JSON data
		err = json.Unmarshal(body, &jsonData)
		if err != nil {
			http.Error(w, "Error unmarshaling JSON", http.StatusBadRequest)
			return
		}
		rawECDSAPrivKey, err := ReadJWTKeyFromFile(configuration.JWTKeyPath.VerifierPath)
		if err != nil {
			log.Fatalf("Error reading keys for JWT: %v", err)
		}
		id := jsonData["Id"]
		key, err := jwk.FromRaw(rawECDSAPrivKey)
		if err != nil {
			log.Fatalf("Error importing key for JWT: %v\n", err)
		}
		ar, err := arBroker.ReadFirstMatch(id)
		if err != nil {
			log.Fatalf("Error reading attestation result from pool: %v\n", err)
		}

		buf, err := ar.Sign(jwa.ES256, key)
		if err != nil {
			log.Fatalf("Error signing the attestation result: %v\n", err)
		}
		publicKey, err := key.PublicKey()
		if err != nil {
			log.Fatalf("Error extracting public key: %v\n", err)
		}

		finalAR := AttestationResult{JWT: buf, JWK: publicKey}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(finalAR)
		if err != nil {
			log.Fatalf("failed to encode attestation result %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write(b.Bytes())
	})

	url := fmt.Sprintf("%s:%d",
		configuration.VerifierNet.Ip, configuration.VerifierNet.Port)
	if err := http.ListenAndServe(url, nil); err != http.ErrServerClosed {
		panic(err)
	}

	return 0
}

func pingAPI(url string) error {
	// Esegui una richiesta GET
	resp, err := http.Get(url)
	if err != nil {
		return err // Se c'è un errore, il server non è disponibile
	}
	defer resp.Body.Close()

	// Controlla se la risposta HTTP è OK (status 200)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server non disponibile: %d", resp.StatusCode)
	}

	return nil // La richiesta è andata a buon fine
}

type AgentNet struct {
	Ip   string
	Port int
}

type AttestationResultUpdate struct {
	DeviceID string  `json:"DeviceID"`
	JWT      []byte  `json:"JWT"`
	JWK      jwk.Key `json:"JWK"`
}

type AttestationResult struct {
	JWT []byte
	JWK jwk.Key
}

func GenerateJWTKey(verbose bool) error {

	privJWT, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating ECDSA key: %v", err)

	}

	// Encode private key to PEM format
	privBytes, err := x509.MarshalECPrivateKey(privJWT)
	if err != nil {
		log.Fatalf("Error marshalling private key: %v", err)
		return err
	}

	// Create PEM block with the private key
	privPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}

	// Open file to write the private key
	file, err := os.Create("verify_ecdsa_private_key.pem")
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
		return err
	}
	defer file.Close()

	// Write the private key in PEM format to the file
	err = pem.Encode(file, privPem)
	if err != nil {
		log.Fatalf("Error writing private key to file: %v", err)
		return err
	}
	if verbose {
		log.Println("ECDSA private key saved to verify_ecdsa_private_key.pem")
	}

	return nil

}

func ReadJWTKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	// Open the private key file
	privFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening private key file: %v", err)
		return nil, err
	}
	defer privFile.Close()

	privBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Decode the PEM block from the file
	privPem, _ := pem.Decode(privBytes)
	if privPem == nil || privPem.Type != "EC PRIVATE KEY" {
		log.Fatalf("No valid PEM block found in file")
		return nil, err
	}

	// Parse the ECDSA private key from the PEM block
	priv, err := x509.ParseECPrivateKey(privPem.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
		return nil, err
	}

	return priv, nil
}

func ReadConf() c.Configurations {
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath("./configV")

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

type CircularBuffer struct {
	Broker   []*e.AttestationResult
	M        sync.Mutex
	head     int
	tail     int
	size     int
	capacity int
}

func NewCircularBuffer(capacity int) *CircularBuffer {
	return &CircularBuffer{
		Broker:   make([]*e.AttestationResult, capacity),
		head:     0,
		tail:     0,
		size:     0,
		capacity: capacity,
	}
}

func (cb *CircularBuffer) Push(value *e.AttestationResult) error {
	cb.M.Lock()
	defer cb.M.Unlock()

	if cb.size == cb.capacity {
		// Buffer is full, overwrite the oldest element (head)
		cb.head = (cb.head + 1) % cb.capacity
	} else {
		cb.size++
	}

	cb.Broker[cb.tail] = value
	cb.tail = (cb.tail + 1) % cb.capacity

	return nil
}

func (cb *CircularBuffer) Pop() error {
	cb.M.Lock()
	defer cb.M.Unlock()

	if cb.size == 0 {
		return errors.New("buffer is empty")
	}

	cb.head = (cb.head + 1) % cb.capacity
	cb.size--

	return nil
}

func (cb *CircularBuffer) ReadFirstMatch(value string) (*e.AttestationResult, error) {
	cb.M.Lock()
	defer cb.M.Unlock()

	if cb.size == 0 {
		return nil, errors.New("buffer is empty")
	}

	// Search through the buffer from the head to the tail
	for i := 0; i < cb.size; i++ {
		// Calculate the correct position using circular indexing
		if cb.Broker[(cb.head+i)%cb.capacity].Submods[value] != nil {
			// Return the first match: the value and its index
			return cb.Broker[(cb.head+i)%cb.capacity], nil
		}
	}

	// If value is not found
	return nil, fmt.Errorf("id %s not found in the buffer", value)
}
