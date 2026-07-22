package register

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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

	"database/sql"

	h "agent_db_handler"
	cR "configR"
	fq "first_quote_handler"
	"ima_verifier"
	rh "reference_handler"
	t "tpm_db_handler"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/veraison/corim/comid"
	e "github.com/veraison/ear"
	"github.com/veraison/swid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	pb "github.com/google/go-tpm-tools/proto/tpm"

	_ "github.com/lib/pq"
)

type Ext struct {
	FileName string `json:"filename,omitempty"`
}

func Register(verbose bool) int {

	configurationR := ReadConfR()

	if verbose {
		log.Println("Register started...")
	}

	secret := make([]byte, 32)
	nonce := make([]byte, 32)

	err := h.InitializeAgentDatabase(configurationR)
	if err != nil {
		log.Fatalf("Error initializing Agent DB: %v", err)
	}

	err = t.InitializeTPMDatabase(configurationR)
	if err != nil {
		log.Fatalf("Error initializing TPM DB: %v", err)
	}
	if configurationR.CreateJWTKeys.Create {
		err := GenerateJWTKey(verbose)
		if err != nil {
			log.Fatalf("Error creating keys for JWT: %v", err)
		}
	}

	http.HandleFunc("/insertreference", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		newReference := ima_verifier.RefID{}
		whitelistId := uuid.New()
		newReference.Id = whitelistId.String()

		var jsonFratm map[string]interface{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = json.Unmarshal(body, &jsonFratm)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		meas := (jsonFratm["measurements"]).([]interface{})
		var meaMap []map[string]interface{}
		var digestVect []interface{}
		var filenameVect []interface{}
		var finalDigests [][]string
		var finalFilenames []string
		for i := 0; i < len(meas); i++ {
			meaMap = append(meaMap, meas[i].(map[string]interface{}))
			cioa := meaMap[i]["value"].(map[string]interface{})
			digestVect = cioa["digests"].([]interface{})
			filenameVect = append(filenameVect, cioa["filename"])

			digests := make([]string, len(digestVect))
			for i := 0; i < len(digests); i++ {
				digests[i] = digestVect[i].(string)
			}
			finalDigests = append(finalDigests, digests)

			fileNames := make([]string, len(filenameVect))
			for i := 0; i < len(fileNames); i++ {
				fileNames[i] = filenameVect[i].(string)

			}
			finalFilenames = fileNames

		}
		var extension Ext
		for i := 0; i < len(finalDigests); i++ {

			fileHash := strings.Split(finalDigests[i][0], ";")
			hash := fileHash[0]
			val := fileHash[1]
			var m comid.Measurement

			switch hash {
			case "sha-256":
				decodedHash, err := base64.StdEncoding.DecodeString(val)
				if err != nil {
					log.Fatalf("%v", err)
				}
				m.AddDigest(swid.Sha256, decodedHash)

			}

			extension.FileName = finalFilenames[i]
			extension2 := extension
			m.Val.RegisterExtensions(&extension2)
			newReference.References.Measurements.AddMeasurement(&m)

		}

		err = newReference.References.Measurements.Valid()
		if err != nil {
			log.Fatal("Error validation new Reference Value", err)
		}

		//Connect to Mongo
		//uri := fmt.Sprintf("mongodb+srv://%s:%s@%s",
		//	configuration.Mongodb.MongoUser, configuration.Mongodb.MongoPassword, configuration.Mongodb.MongoURL)
		uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/?timeoutMS=5000", configurationR.Mongodb.MongoUser, configurationR.Mongodb.MongoPassword, configurationR.Mongodb.MongoIP, configurationR.Mongodb.MongoPort)
		client, err := mongo.NewClient(options.Client().ApplyURI(uri))
		if err != nil {
			log.Fatal("Error creating client to connecto to Mongo:", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = client.Connect(ctx)
		if err != nil {
			log.Fatal("Error connectiong to mongo:", err)
		}
		defer client.Disconnect(ctx)

		err = client.Ping(ctx, readpref.Primary())
		if err != nil {
			log.Fatal(err)
		}

		referenceDatabase := client.Database("reference_values")
		referencesCollection := referenceDatabase.Collection("references")

		rh.InsertReference(referencesCollection, ctx, newReference)

	})

	var PubKey string

	http.HandleFunc("/agentaddr", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ipPort := &AgentNet{}
		err := json.NewDecoder(r.Body).Decode(ipPort)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

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

		url := fmt.Sprintf("http://%s:%d/startregister",
			ipPort.Ip, ipPort.Port)
		_, _ = http.Post(url, "application/json", b)

	})

	http.HandleFunc("/insertTPMvendor", func(w http.ResponseWriter, r *http.Request) {
		dataSourceName := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			configurationR.PostgresDatabase.DBUser, configurationR.PostgresDatabase.DBPassword, configurationR.PostgreServer.Ip, configurationR.PostgreServer.Port, configurationR.PostgresDatabase.DBName)
		// Establish a connection to the PostgreSQL database
		db, err := sql.Open("postgres", dataSourceName)
		if err != nil {
			log.Fatal("Error connecting to the database: ", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatal("Not Connected ", err)
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var vendor t.TPMVendor
		err = json.NewDecoder(r.Body).Decode(&vendor)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = t.InsertTPMVendor(db, vendor.Name, vendor.TCGIdentifier, vendor.PlatformModel, vendor.FirmwareVersion)
		if err != nil {
			http.Error(w, "Error inserting vendor", http.StatusInternalServerError)
			return
		}
		log.Println("New Vendor inserted:", vendor)
		w.WriteHeader(http.StatusCreated)
	})

	http.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var firstReq string
		err = json.NewDecoder(r.Body).Decode(&firstReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if verbose {
			log.Println("Received request!", firstReq, r.RemoteAddr)
		}
		_, err = rand.Read(nonce)
		if err != nil {
			log.Fatalf("creating nonce: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write(nonce)
		if verbose {
			log.Println("Created nonce:", base64.StdEncoding.EncodeToString(nonce))
		}
	})

	var id uuid.UUID
	arBroker := NewCircularBuffer(10)

	http.HandleFunc("/firstquote", func(w http.ResponseWriter, r *http.Request) {
		id = uuid.New()
		dataSourceName := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			configurationR.PostgresDatabase.DBUser, configurationR.PostgresDatabase.DBPassword, configurationR.PostgreServer.Ip, configurationR.PostgreServer.Port, configurationR.PostgresDatabase.DBName)
		// Establish a connection to the PostgreSQL database
		db, err := sql.Open("postgres", dataSourceName)
		if err != nil {
			log.Fatal("Error connecting to the database: ", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatal("Not Connected ", err)
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req FirstQuote
		err = json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if verbose {
			log.Println("Received first quote!")
		}

		tpmEKCertificate, err := t.LoadCertificateFromPEM(req.EKCertificate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		/*decodedEK, err := t.DecodePublicKeyFromPEM(tpmEKCertificate.PublicKey.(string))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}*/
		// Verify that the public key in the certificate matches the provided public key
		/*if !decodedEK.Equal(tpmEKCertificate.PublicKey) {
			http.Error(w, "Error", http.StatusBadRequest)
			return
		}*/
		// Get intermediate CA's certificate
		intermediateCA, err := t.GetCertificateByCommonName(db, tpmEKCertificate.Issuer.CommonName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		intermediateCACert, err := t.LoadCertificateFromPEM(intermediateCA.PEMCertificate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Get intermediate CA's certificate
		rootCA, err := t.GetCertificateByCommonName(db, intermediateCACert.Issuer.CommonName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rootCACert, err := t.LoadCertificateFromPEM(rootCA.PEMCertificate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		t.VerifyEKCertificateChain(db, tpmEKCertificate, intermediateCACert, rootCACert)

		tpmPub, err := tpm2.DecodePublic(req.AKPubBlob)
		if err != nil {
			log.Fatalf("Failed decoding public blob: %v", err)
		}
		pubAK, err := tpmPub.Key()
		if err != nil {
			log.Fatalf("decode public key: %v", err)
		}
		pubAKDER, err := x509.MarshalPKIXPublicKey(pubAK)
		if err != nil {
			log.Fatalf("encoding public key: %v", err)
		}
		bAK := &pem.Block{Type: "PUBLIC KEY", Bytes: pubAKDER}
		var PublicKeyRow bytes.Buffer
		err = pem.Encode(&PublicKeyRow, bAK)
		if err != nil {
			log.Fatalf("encoding pem: %v", err)
		}
		PubKey = PublicKeyRow.String()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			err = h.CreateAgent(db, id.String(), r.RemoteAddr, PubKey, req.WhitelistID, "Registration Failure")
			if err != nil {
				log.Fatal("Error creating record: ", err)
			}
			return
		}

		if verbose {
			log.Println("EK Certificate Validated! Let's check the quote...")
		}
		switch configurationR.FirstQuote.HashAlgo {
		case "sha256":
			err = fq.VerifyQuote(req.Quote[0], pubAK, req.Nonce)
			if err != nil {
				log.Println("Failed to verify the first quote:", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				err = h.CreateAgent(db, id.String(), r.RemoteAddr, PubKey, req.WhitelistID, "Registration Failure")
				if err != nil {
					log.Fatal("Error creating record: ", err)
				}
				return
			}
			if verbose {
				log.Println("Quotes (SHA256) are fine, continue with registration!")
			}

		case "sha384":
			err = fq.VerifyQuote(req.Quote[1], pubAK, req.Nonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				err = h.CreateAgent(db, id.String(), r.RemoteAddr, PubKey, req.WhitelistID, "Registration Failure")
				if err != nil {
					log.Fatal("Error creating record: ", err)
				}
				return
			}
			if verbose {
				log.Println("Quotes (SHA384) are fine, continue with registration!")
			}

		case "sha512":
			err = fq.VerifyQuote(req.Quote[2], pubAK, req.Nonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				err = h.CreateAgent(db, id.String(), r.RemoteAddr, PubKey, req.WhitelistID, "Registration Failure")
				if err != nil {
					log.Fatal("Error creating record: ", err)
				}
				return
			}
			if verbose {
				log.Println("Quotes (SHA512) are fine, continue with registration!")
			}

		default:
			log.Fatalf("unsupported hash algorithm: %v", configurationR.FirstQuote.HashAlgo)
		}

		w.WriteHeader(http.StatusOK)
		ar := e.NewAttestationResult(id.String(), configurationR.RegisterIdentity.Build, configurationR.RegisterIdentity.Developer)
		ar.Submods[id.String()].TrustVector.Configuration = e.NoClaim
		ar.Submods[id.String()].TrustVector.Hardware = e.NoClaim
		ar.Submods[id.String()].TrustVector.InstanceIdentity = e.NoClaim
		ar.Submods[id.String()].TrustVector.Executables = e.ApprovedBootClaim
		ar.Submods[id.String()].Status = e.NewTrustTier(e.TrustTierAffirming) // as TrustTierNonce means appraisal could not be conducted for whatever reason (e.g., a processing error).
		*ar.IssuedAt = time.Now().Unix()
		arBroker.Push(ar)
	})

	// Receive registration data, check namedata, create and send back the challenge
	http.HandleFunc("/registration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rawData := &Data{}
		err := json.NewDecoder(r.Body).Decode(rawData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if verbose {
			log.Println("Got EK activation material data!")
		}

		pubBlob := rawData.PubBlob
		nameData := rawData.NameData
		ekTPMPubRaw := rawData.EKTPMPub

		// Verify digest matches the public blob that was provided.
		name, err := tpm2.DecodeName(bytes.NewBuffer(nameData)) //tpm2.Name is a struct composed by 2 elements, a Handle and a Digest
		if err != nil {
			log.Fatalf("unpacking name: %v", err)
		}
		if name.Digest == nil {
			log.Fatalf("name was not a digest")
		}
		h, err := name.Digest.Alg.Hash() // so I extract the hash algorithm that has been used to calculate the name
		if err != nil {
			log.Fatalf("failed to get name hash: %v", err)
		}

		pubHash := h.New() // I create a new digest given the public blob that was provided
		pubHash.Write(pubBlob)
		pubDigest := pubHash.Sum(nil)
		if !bytes.Equal(name.Digest.Value, pubDigest) { // and check if the digest that's been calculated over the public blob
			log.Fatalf("name was not for public blob") // is the same that was provided (name)
		}
		ekTPMPub, err := tpm2.DecodePublic(ekTPMPubRaw)
		if err != nil {
			log.Fatalf("decode ek public key: %v", err)
		}
		ekPub, err := ekTPMPub.Key()
		if err != nil {
			log.Fatalf("retreiving public key: %v", err)
		}
		if verbose {
			log.Println("Creating challenge...")
		}
		// Generate Challenge
		_, err = rand.Read(secret)
		if err != nil {
			log.Fatalf("creating secret: %v", err)
		}
		symBlockSize := 16
		credBlob, encSecret, err := credactivation.Generate(name.Digest, ekPub, symBlockSize, secret)
		if err != nil {
			log.Fatalf("generate credential: %v", err)
		}

		w.WriteHeader(http.StatusAccepted)
		challenge := append(credBlob, encSecret...)

		w.Write(challenge)
		if verbose {
			log.Println("Challenge Sent!")
		}

	})

	// Check challenge result
	http.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		dataSourceName := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			configurationR.PostgresDatabase.DBUser, configurationR.PostgresDatabase.DBPassword, configurationR.PostgreServer.Ip, configurationR.PostgreServer.Port, configurationR.PostgresDatabase.DBName)
		// Establish a connection to the PostgreSQL database
		db, err := sql.Open("postgres", dataSourceName)
		if err != nil {
			log.Fatal("Error connecting to the database: ", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatal("Not Connected ", err)
		}
		challengeResult := ChallengeSolution{}
		err = json.NewDecoder(r.Body).Decode(&challengeResult)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !bytes.Equal(challengeResult.Solution, secret) {
			log.Fatalf("wrong challenge response: %v", err)
			err = h.CreateAgent(db, id.String(), r.RemoteAddr, PubKey, challengeResult.WhitelistID, "Registration Failure")
			if err != nil {
				log.Fatal("Error creating record: ", err)
			}
		}
		if verbose {
			log.Println("Challenge Solved!")
		}
		if challengeResult.WhitelistID == "" {
			log.Fatalf("null Whitelist ID... insert one")
		}
		// Connect to Mongo
		//uri := fmt.Sprintf("mongodb+srv://%s:%s@%s",
		//	configuration.Mongodb.MongoUser, configuration.Mongodb.MongoPassword, configuration.Mongodb.MongoURL)
		uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/?timeoutMS=5000", configurationR.Mongodb.MongoUser, configurationR.Mongodb.MongoPassword, configurationR.Mongodb.MongoIP, configurationR.Mongodb.MongoPort)
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

		_, err = referencesCollection.FindOne(ctx, bson.M{"id": challengeResult.WhitelistID}).Raw()
		if err != nil {
			log.Fatalf("No whitelist ID found in mongo %v", err)
		} else {
			db := client.Database("admin")
			var existingUser bson.M
			err = db.RunCommand(context.Background(), bson.D{
				{Key: "usersInfo", Value: configurationR.Mongodb.MongoUserVerifier},
			}).Decode(&existingUser)

			if err == nil {
				users, ok := existingUser["users"].(bson.A)
				if ok && len(users) > 0 {
					user := users[0].(bson.M)
					roles := user["roles"].(bson.A)
					hasReadRole := false

					for _, role := range roles {
						r := role.(bson.M)
						if r["role"] == "read" && r["db"] == "reference_values" {
							hasReadRole = true
							break
						}
					}

					if !hasReadRole {
						fmt.Println("User exixts, let's update the roles...")
						updateRolesCmd := bson.D{
							{Key: "updateUser", Value: configurationR.Mongodb.MongoUserVerifier},
							{Key: "roles", Value: bson.A{
								bson.D{
									{Key: "role", Value: "read"},
									{Key: "db", Value: "reference_values"},
								},
							}},
						}

						err = db.RunCommand(context.Background(), updateRolesCmd).Err()
						if err != nil {
							log.Fatal("Error updating the roles:", err)
						}
						fmt.Println("Roles updated properly")
					}

				} else {
					createUserCmd := bson.D{
						{Key: "createUser", Value: configurationR.Mongodb.MongoUserVerifier},
						{Key: "pwd", Value: configurationR.Mongodb.MongoPasswordVerifier},
						{Key: "roles", Value: bson.A{
							bson.D{
								{Key: "role", Value: "read"},
								{Key: "db", Value: "reference_values"},
							},
						}},
					}

					result := db.RunCommand(context.Background(), createUserCmd)
					if result.Err() != nil {
						log.Fatal(result.Err())
					}

				}

			}
		}

		// Create record in postgresql database
		err = h.CreateAgent(db, id.String(), r.Header.Get("X-Forwarded-For"), PubKey, challengeResult.WhitelistID, "Registered")
		if err != nil {
			log.Fatal("Error creating record: ", err)
		}

		if verbose {
			log.Println("Created record with ID:", id.String(), "whitelistID:", challengeResult.WhitelistID)
		}

		if configurationR.StartRegistration.Start {
			rawIpPort, err := h.ReadIP_Port(db, id.String())
			if err != nil {
				log.Fatalf("failed retrieving ip_port %v", err)
			}
			//fmt.Println(rawIpPort)
			ipPort := &AgentNet{}
			ipPort.Ip = strings.Split(rawIpPort, ":")[0]
			ipPort.Port = configurationR.StartAttestation.Port
			url := fmt.Sprintf("http://%s:%d/shutdown",
				ipPort.Ip, ipPort.Port)
			data := id.String()
			b := new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(data)
			if err != nil {
				log.Fatalf("failed to encode nonce %v", err)
			}
			_, _ = http.Post(url, "application/json", b)
		} else {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Don't forget to close the connection:
			conn.Write([]byte("HTTP/1.0 200 OK\r\n"))
			conn.Write([]byte("Content-Type: application/json\r\n"))
			conn.Write([]byte("\r\n")) // Indica la fine degli header HTTP
			conn.Write([]byte(id.String()))
			conn.Close()

		}

		if configurationR.StartAttestation.Start {

			jsonData := make(map[string]string)
			jsonData["Id"] = id.String()
			b := new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(jsonData)
			if err != nil {
				log.Fatalf("failed encode id %v", err)
			}

			url := fmt.Sprintf("http://%s:%d/deviceid",
				configurationR.VerifierNet.Ip, configurationR.VerifierNet.Port)
			_, _ = http.Post(url, "application/json", b)
		}

		log.Println("Device", id.String(), "registered")

		return
	})

	http.HandleFunc("/registrationresult", func(w http.ResponseWriter, r *http.Request) {
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
		rawECDSAPrivKey, err := ReadJWTKeyFromFile(configurationR.JWTKeyPath.RegisterPath)
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
			log.Fatalf("failed to encode registration result %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write(b.Bytes())
	})

	http.HandleFunc("/updatestate", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Unable to read body", http.StatusBadRequest)
			return
		}

		// Decodifica il corpo JSON in una struttura Go
		var arUpdate AttestationResultUpdate
		err = json.Unmarshal(body, &arUpdate)
		if err != nil {
			http.Error(w, "Error decoding body", http.StatusBadRequest)
			return
		}

		dataSourceName := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			configurationR.PostgresDatabase.DBUser, configurationR.PostgresDatabase.DBPassword, configurationR.PostgreServer.Ip, configurationR.PostgreServer.Port, configurationR.PostgresDatabase.DBName)
		// Establish a connection to the PostgreSQL database
		db, err := sql.Open("postgres", dataSourceName)
		if err != nil {
			log.Fatal("Error connecting to the database: ", err)
		}
		defer db.Close()

		if err = db.Ping(); err != nil {
			log.Fatal("Not Connected ", err)
		}

		var ar e.AttestationResult
		err = ar.Verify(arUpdate.JWT, jwa.ES256, arUpdate.JWK)
		if err != nil {
			log.Println("Error validating JWT", err)
			err = h.UpdateState(db, string(arUpdate.DeviceID), "Attestation Failure")
			if err != nil {
				log.Println("Error updating state", err)
			}
			return
		}

		err = h.UpdateState(db, string(arUpdate.DeviceID), "Attested")
		if err != nil {
			log.Println("Error updating state", err)
		}

	})

	url := fmt.Sprintf("%s:%d",
		configurationR.RegisterNet.Ip, configurationR.RegisterNet.Port)
	if err := http.ListenAndServe(url, nil); err != http.ErrServerClosed {
		panic(err)
	}

	return 0
}

type AttestationResultUpdate struct {
	DeviceID string  `json:"DeviceID"`
	JWT      []byte  `json:"JWT"`
	JWK      jwk.Key `json:"JWK"`
}

func (a *AttestationResultUpdate) UnmarshalJSON(data []byte) error {
	var temp struct {
		DeviceID string          `json:"DeviceID"`
		JWT      []byte          `json:"JWT"`
		JWK      json.RawMessage `json:"JWK"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	a.DeviceID = temp.DeviceID
	a.JWT = temp.JWT

	if temp.JWK != nil {
		key, err := jwk.ParseKey(temp.JWK)
		if err != nil {
			return fmt.Errorf("error parsing JWK: %v", err)
		}
		a.JWK = key
	}

	return nil
}

type AttestationResult struct {
	JWT []byte
	JWK jwk.Key
}

type FirstQuote struct {
	EKCertificate string
	Quote         []*pb.Quote
	AKPubBlob     []byte
	Nonce         []byte
	WhitelistID   string
}

type Data struct {
	PubBlob  []byte
	NameData []byte
	EKTPMPub []byte
}

type ChallengeSolution struct {
	Solution    []byte
	WhitelistID string
}

type AgentNet struct {
	Ip   string
	Port int
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
	file, err := os.Create("register_ecdsa_private_key.pem")
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
		log.Println("ECDSA private key saved to register_ecdsa_private_key.pem")
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

func ReadConfR() cR.Configurations {
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath("./configR")

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yml")
	var configuration cR.Configurations

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
