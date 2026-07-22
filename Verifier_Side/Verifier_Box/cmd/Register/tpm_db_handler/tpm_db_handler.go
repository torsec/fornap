package tpm_db_handler

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"

	c "configR"

	x509ext "github.com/google/go-attestation/x509"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

type TPMVendor struct {
	VendorID        string
	Name            string
	TCGIdentifier   string
	PlatformModel   string
	FirmwareVersion string
}

var TPMManufacturers = []TPMVendor{
	{Name: "AMD", TCGIdentifier: "id:414D4400", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Atmel", TCGIdentifier: "id:41544D4C", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Broadcom", TCGIdentifier: "id:4252434D", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Cisco", TCGIdentifier: "id:4353434F", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Flyslice Technologies", TCGIdentifier: "id:464C5953", PlatformModel: "", FirmwareVersion: ""},
	{Name: "HPE", TCGIdentifier: "id:48504500", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Huawei", TCGIdentifier: "id:48495349", PlatformModel: "", FirmwareVersion: ""},
	{Name: "IBM", TCGIdentifier: "id:49424D00", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Infineon", TCGIdentifier: "id:49465800", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Intel", TCGIdentifier: "id:494E5443", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Lenovo", TCGIdentifier: "id:4C454E00", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Microsoft", TCGIdentifier: "id:4D534654", PlatformModel: "", FirmwareVersion: ""},
	{Name: "National Semiconductor", TCGIdentifier: "id:4E534D20", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Nationz", TCGIdentifier: "id:4E545A00", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Nuvoton Technology", TCGIdentifier: "id:4E544300", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Qualcomm", TCGIdentifier: "id:51434F4D", PlatformModel: "", FirmwareVersion: ""},
	{Name: "SMSC", TCGIdentifier: "id:534D5343", PlatformModel: "", FirmwareVersion: ""},
	{Name: "ST Microelectronics", TCGIdentifier: "id:53544D20", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Samsung", TCGIdentifier: "id:534D534E", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Sinosun", TCGIdentifier: "id:534E5300", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Texas Instruments", TCGIdentifier: "id:54584E00", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Winbond", TCGIdentifier: "id:57454300", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Fuzhouk Rockchip", TCGIdentifier: "id:524F4343", PlatformModel: "", FirmwareVersion: ""},
	{Name: "Google", TCGIdentifier: "id:474F4F47", PlatformModel: "", FirmwareVersion: ""},
}

type TPMCACertificate struct {
	CertificateID  string
	CommonName     string
	PEMCertificate string
}

var knownCACerts = []TPMCACertificate{
	{CommonName: "Infineon OPTIGA(TM) RSA Manufacturing CA 003", PEMCertificate: "-----BEGIN CERTIFICATE-----\nMIIFszCCA5ugAwIBAgIEasM5FDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJE\nRTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJP\nUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkg\nUlNBIFJvb3QgQ0EwHhcNMTQxMTI0MTUzNzE2WhcNMzQxMTI0MTUzNzE2WjCBgzEL\nMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEa\nMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9Q\nVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAuUD5SLLVYRmuxDjT3cWQbRTywTWUVFE3EupJQZjJ\n9mvFc2KcjpQv6rpdaT4JC33P1M9iJgrHwYO0AZlGl2FcFpSNkc/3CWoMTT9rOdwS\n/MxlNSkxwTz6IAYUYh7+pd7T49NpRRGZ1dOMfyOxWgA4C0g3EP/ciIvA2cCZ95Hf\nARD9NhuG2DAEYGNRSHY2d/Oxu+7ytzkGFFj0h1jnvGNJpWNCf3CG8aNc5gJAduMr\nWcaMHb+6fWEysg++F2FLav813+/61FqvSrUMsQg0lpE16KBA5QC2Wcr/kLZGVVGc\nuALtgJ/bnd8XgEv7W8WG+jyblUe+hkZWmxYluHS3yJeRbwIDAQABo4IBODCCATQw\nVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vcGtpLmluZmluZW9u\nLmNvbS9PcHRpZ2FSc2FSb290Q0EvT3B0aWdhUnNhUm9vdENBLmNydDAdBgNVHQ4E\nFgQUQLhoK40YRQorBoSdm1zZb0zd9L4wDgYDVR0PAQH/BAQDAgAGMBIGA1UdEwEB\n/wQIMAYBAf8CAQAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL3BraS5pbmZpbmVv\nbi5jb20vT3B0aWdhUnNhUm9vdENBL09wdGlnYVJzYVJvb3RDQS5jcmwwFQYDVR0g\nBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBTcu1ar8Rj8ppp1ERBlhBKe1UGS\nuTAQBgNVHSUECTAHBgVngQUIATANBgkqhkiG9w0BAQsFAAOCAgEAeUzrsGq3oQOT\nmF7g71TtMMndwPxgZvaB4bAc7dNettn5Yc1usikERfvJu4/iBs/Tdl6z6TokO+6V\nJuBb6PDV7f5MFfffeThraPCTeDcyYBzQRGnoCxc8Kf81ZJT04ef8CQkkfuZHW1pO\n+HHM1ZfFfNdNTay1h83x1lg1U0KnlmJ5KCVFiB94owr9t5cUoiSbAsPcpqCrWczo\nRsg1aTpokwI8Y45lqgt0SxEmQw2PIAEjHG2GQcLBDeI0c7cK5OMEjSMXStJHmNbp\nu4RHXzd+47nCD2kGV8Bx5QnK8qDVAFAe/UTDQi5mTtDFRL36Nns7jz8USemu+bw9\nl24PN73rKcB2wNF2/oFTLPHkdYfTKYGXG1g2ZkDcTAENSOq3fcTfAuyHQozBwYHG\nGGyyPHy6KvLkqMQuqeDv0QxGOtE+6cedFMP2D9bMaujR389mSm7DE6YyNQClRW7w\nJ1+rNYuN2vErvB96ir1zljXq0yMxrm5nTeiAT4p5eoFqoeSYDbFljt/f+PebREiO\nnJIy4fdvKlHAf70gPdYpYipc4oTZxLeWjDQxRFFBDFrnLdlPSg6zSL2Q3ANAEI3y\nMtHaEaU0wbaBvezyzMUHI5nLnYFL+QRP4N2OFNI/ejBaEpmIXzf6+/eF40MNLHuR\n9/B93Q+hpw8O6XZ7qx697I+5+smLlPQ=\n-----END CERTIFICATE-----"},
	{CommonName: "Infineon OPTIGA(TM) RSA Root CA", PEMCertificate: "-----BEGIN CERTIFICATE-----\nMIIFqzCCA5OgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJERTEh\nMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ\nR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgUlNB\nIFJvb3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYD\nVQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYD\nVQQLDBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElH\nQShUTSkgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC\nAQC7E+gc0B5T7awzux66zMMZMTtCkPqGv6a3NVx73ICg2DSwnipFwBiUl9soEodn\n25SVVN7pqmvKA2gMTR5QexuYS9PPerfRZrBY00xyFx84V+mIRPg4YqUMLtZBcAwr\nR3GO6cffHp20SBH5ITpuqKciwb0v5ueLdtZHYRPq1+jgy58IFY/vACyF/ccWZxUS\nJRNSe4ruwBgI7NMWicxiiWQmz1fE3e0mUGQ1tu4M6MpZPxTZxWzN0mMz9noj1oIT\nZUnq/drN54LHzX45l+2b14f5FkvtcXxJ7OCkI7lmWIt8s5fE4HhixEgsR2RX5hzl\n8XiHiS7uD3pQhBYSBN5IBbVWREex1IUat5eAOb9AXjnZ7ivxJKiY/BkOmrNgN8k2\n7vOS4P81ix1GnXsjyHJ6mOtWRC9UHfvJcvM3U9tuU+3dRfib03NGxSPnKteL4SP1\nbdHfiGjV3LIxzFHOfdjM2cvFJ6jXg5hwXCFSdsQm5e2BfT3dWDBSfR4h3Prpkl6d\ncAyb3nNtMK3HR5yl6QBuJybw8afHT3KRbwvOHOCR0ZVJTszclEPcM3NQdwFlhqLS\nghIflaKSPv9yHTKeg2AB5q9JSG2nwSTrjDKRab225+zJ0yylH5NwxIBLaVHDyAEu\n81af+wnm99oqgvJuDKSQGyLf6sCeuy81wQYO46yNa+xJwQIDAQABo0IwQDAdBgNV\nHQ4EFgQU3LtWq/EY/KaadREQZYQSntVBkrkwDgYDVR0PAQH/BAQDAgAGMA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGHTBUx3ETIXYJsaAgb2pyyN\nUltVL2bKzGMVSsnTCrXUU8hKrDQh3jNIMrS0d6dU/fGaGJvehxmmJfjaN/IFWA4M\nBdZEnpAe2fJEP8vbLa/QHVfsAVuotLD6QWAqeaC2txpxkerveoV2JAwj1jrprT4y\nrkS8SxZuKS05rYdlG30GjOKTq81amQtGf2NlNiM0lBB/SKTt0Uv5TK0jIWbz2WoZ\ngGut7mF0md1rHRauWRcoHQdxWSQTCTtgoQzeBj4IS6N3QxQBKV9LL9UWm+CMIT7Y\nnp8bSJ8oW4UdpSuYWe1ZwSjZyzDiSzpuc4gTS6aHfMmEfoVwC8HN03/HD6B1Lwo2\nDvEaqAxkya9IYWrDqkMrEErJO6cqx/vfIcfY/8JYmUJGTmvVlaODJTwYwov/2rjr\nla5gR+xrTM7dq8bZimSQTO8h6cdL6u+3c8mGriCQkNZIZEac/Gdn+KwydaOZIcnf\nRdp3SalxsSp6cWwJGE4wpYKB2ClM2QF3yNQoTGNwMlpsxnU72ihDi/RxyaRTz9OR\npubNq8Wuq7jQUs5U00ryrMCZog1cxLzyfZwwCYh6O2CmbvMoydHNy5CU3ygxaLWv\nJpgZVHN103npVMR3mLNa3QE+5MFlBlP3Mmystu8iVAKJas39VO5y5jad4dRLkwtM\n6sJa8iBpdRjZrBp5sJBI\n-----END CERTIFICATE-----\n"},
}

func InitializeTPMDatabase(configuration c.Configurations) error {
	var err error
	dataSourceName := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		configuration.PostgresDatabase.DBUser, configuration.PostgresDatabase.DBPassword, configuration.PostgreServer.Ip, configuration.PostgreServer.Port, configuration.PostgresDatabase.DBName)
	// Establish a connection to the PostgreSQL database
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		log.Fatal("Error connecting to the database: ", err)
	}
	defer db.Close()

	// Create TPM Certificates table
	createTPMCertTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_ca_certificates (
		certificateId SERIAL PRIMARY KEY,
		cn TEXT NOT NULL UNIQUE,
		PEMcertificate TEXT NOT NULL UNIQUE
	);`

	if _, err = db.Exec(createTPMCertTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM certificates table: %w", err)
	}

	// Create TPM Certificates table
	createTPMVendorTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_vendors (
		vendorId SERIAL,
		name TEXT NOT NULL,
		TCGIdentifier TEXT NOT NULL,
		PlatformModel TEXT,
		FirmwareVersion TEXT
	);`

	if _, err = db.Exec(createTPMVendorTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM vendors table: %w", err)
	}

	err = initTPMVendors(db)
	if err != nil {
		return fmt.Errorf("failed to insert default TPM vendors: %v", err)
	}

	err = initCACertificates(db)
	if err != nil {
		return fmt.Errorf("failed to insert known CA certificates: %v", err)
	}

	return nil
}

func initTPMVendors(db *sql.DB) error {
	// Prepare the insert statement
	insertVendorQuery := `INSERT INTO tpm_vendors(name, TCGIdentifier, PlatformModel, FirmwareVersion) VALUES($1, $2, $3, $4) ON CONFLICT DO NOTHING;`
	query, err := db.Prepare(insertVendorQuery)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v", err)
	}

	defer func(query *sql.Stmt) {
		err := query.Close()
		if err != nil {
			return
		}
	}(query)

	// Insert vendors into the database
	for _, vendor := range TPMManufacturers {
		_, err := query.Exec(vendor.Name, vendor.TCGIdentifier, vendor.PlatformModel, vendor.FirmwareVersion)
		if err != nil {
			return fmt.Errorf("error inserting TPM vendor %s: %v", vendor.Name, err)
		}
	}
	return nil
}

func initCACertificates(db *sql.DB) error {
	// Prepare the insert statement
	insertCertificateQuery := `INSERT INTO tpm_ca_certificates (cn, PEMCertificate) VALUES ($1, $2) ON CONFLICT DO NOTHING;`
	query, err := db.Prepare(insertCertificateQuery)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v", err)
	}

	defer func(query *sql.Stmt) {
		err := query.Close()
		if err != nil {
			return
		}
	}(query)

	// Insert vendors into the database
	for _, caCertificate := range knownCACerts {
		_, err := query.Exec(caCertificate.CommonName, caCertificate.PEMCertificate)
		if err != nil {
			return fmt.Errorf("error inserting TPM vendor %s: %v", caCertificate.CommonName, err)
		}
	}
	return nil
}

func LoadCertificateFromPEM(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert, nil
}

func DecodePublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	var rsaPubKey *rsa.PublicKey
	var err error

	switch block.Type {
	case "RSA PUBLIC KEY":
		rsaPubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 public key: %v", err)
		}
	case "PUBLIC KEY":
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %v", err)
		}
		var ok bool
		rsaPubKey, ok = parsedKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}

	return rsaPubKey, nil
}
func GetCertificateByCommonName(db *sql.DB, commonName string) (TPMCACertificate, error) {
	var tpmCert TPMCACertificate
	query := "SELECT certificateId, cn, PEMCertificate FROM tpm_ca_certificates WHERE cn = $1"
	err := db.QueryRow(query, commonName).Scan(&tpmCert.CertificateID, &tpmCert.CommonName, &tpmCert.PEMCertificate)
	if errors.Is(err, sql.ErrNoRows) {
		return tpmCert, errors.New("Certificate not found")
	} else if err != nil {
		return tpmCert, err
	}
	return tpmCert, nil
}

func VerifyEKCertificateChain(db *sql.DB, EKCert, intermediateCACert, rootCACert *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCACert)

	opts := x509.VerifyOptions{
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:         roots,
		Intermediates: intermediates,
	}

	err := HandleTPMSubjectAltName(db, EKCert)
	if err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}

	if _, err := EKCert.Verify(opts); err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}
	return nil
}

func HandleTPMSubjectAltName(db *sql.DB, cert *x509.Certificate) error {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) { // OID for subjectAltName
			subjectAltName, err := x509ext.ParseSubjectAltName(ext)
			if err != nil {
				return err
			}

			// check if Certificate Vendor is a TCG valid one
			TPMVendorId := (subjectAltName.DirectoryNames[0].Names[0].Value).(string)
			_, err = getTPMVendorById(db, TPMVendorId)
			if err != nil {
				return err
			}

			// TODO implement checks on platform model and firmware version
			TPMModel := (subjectAltName.DirectoryNames[0].Names[1].Value).(string)
			_, err = getTPMPlatformModel(db, TPMModel)
			if err != nil {
				return err
			}
			TPMVersion := (subjectAltName.DirectoryNames[0].Names[2].Value).(string)
			_, err = getTPMFirmwareVersion(db, TPMVersion)
			if err != nil {
				return err
			}

			// Remove from UnhandledCriticalExtensions if it's the SAN extension
			for i, unhandledExt := range cert.UnhandledCriticalExtensions {
				if unhandledExt.Equal(ext.Id) {
					// Remove the SAN extension from UnhandledCriticalExtensions
					cert.UnhandledCriticalExtensions = append(cert.UnhandledCriticalExtensions[:i], cert.UnhandledCriticalExtensions[i+1:]...)
					break
				}
			}
			return nil
		}
	}
	return fmt.Errorf("SubjectAltName extension not found")
}
func getTPMVendorById(db *sql.DB, vendorTCGIdentifier string) (TPMVendor, error) {
	var tpmVendor TPMVendor
	query := "SELECT vendorId, name, TCGIdentifier, PlatformModel, FirmwareVersion FROM tpm_vendors WHERE TCGIdentifier = $1"
	err := db.QueryRow(query, vendorTCGIdentifier).Scan(&tpmVendor.VendorID, &tpmVendor.Name, &tpmVendor.TCGIdentifier)
	if errors.Is(err, sql.ErrNoRows) {
		return tpmVendor, errors.New("TPM Vendor not found")
	} else if err != nil {
		return tpmVendor, err
	}
	return tpmVendor, nil
}

func getTPMPlatformModel(db *sql.DB, platformModel string) (string, error) {
	var tpmVendor TPMVendor
	query := "SELECT PlatformModel FROM tpm_vendors WHERE PlatformModel = $1"
	err := db.QueryRow(query, platformModel).Scan(&tpmVendor.PlatformModel)
	if errors.Is(err, sql.ErrNoRows) {
		log.Println("No Platform Model")
	} else if err != nil {
		return tpmVendor.PlatformModel, err
	}
	return tpmVendor.PlatformModel, nil
}

func getTPMFirmwareVersion(db *sql.DB, firmwareVersion string) (string, error) {
	var tpmVendor TPMVendor
	query := "SELECT FirmwareVersion FROM tpm_vendors WHERE FirmwareVersion = $1"
	err := db.QueryRow(query, firmwareVersion).Scan(&tpmVendor.FirmwareVersion)
	if errors.Is(err, sql.ErrNoRows) {
		log.Println("No Firmware Version")
	} else if err != nil {
		return tpmVendor.FirmwareVersion, err
	}
	return tpmVendor.FirmwareVersion, nil
}

func InsertTPMVendor(db *sql.DB, name string, TCGIdentifier string, PlatformModel string, FirmwareVersion string) error {
	_, err := db.Exec("INSERT INTO tpm_vendors(name, TCGIdentifier, PlatformModel, FirmwareVersion) VALUES($1, $2, $3, $4);", name, TCGIdentifier, PlatformModel, FirmwareVersion)
	if err != nil {
		return err
	}
	return nil
}

func ReadConf() c.Configurations {
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath("../../configR")

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
