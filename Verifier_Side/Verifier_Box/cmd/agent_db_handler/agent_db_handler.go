package agent_db_handler

import (
	cR "configR"
	"database/sql"
	"fmt"
	"log"
)

func InitializeAgentDatabase(configurationR cR.Configurations) error {
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

	// Create Auth Keys table
	createDeviceTableQuery := `
	CREATE TABLE IF NOT EXISTS agents (
		id VARCHAR PRIMARY KEY,
		ipaddr_port VARCHAR,
		ak VARCHAR,
		whitelist_id VARCHAR,
		state VARCHAR
	);`

	if _, err = db.Exec(createDeviceTableQuery); err != nil {
		return fmt.Errorf("failed to create agents table: %w", err)
	}

	createUserSQL := fmt.Sprintf(`
	DO $$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_user WHERE usename = '%s') THEN
			CREATE USER %s WITH PASSWORD '%s';
		END IF;
	END $$;`, configurationR.PostgresDatabase.DBUserVerifier, configurationR.PostgresDatabase.DBUserVerifier, configurationR.PostgresDatabase.DBPasswordVerifier)
	grantConnectSQL := fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s;", configurationR.PostgresDatabase.DBName, configurationR.PostgresDatabase.DBUserVerifier)
	grantSelectSQL := fmt.Sprintf("GRANT SELECT ON TABLE agents TO %s;", configurationR.PostgresDatabase.DBUserVerifier)
	//grantSelectSQL := fmt.Sprintf("GRANT SELECT ON ALL TABLES IN SCHEMA agents TO %s;", configurationR.PostgresDatabase.DBUserVerifier)

	// Esecuzione dei comandi SQL
	_, err = db.Exec(createUserSQL)
	if err != nil {
		log.Fatal("Error creating user: ", err)
	}

	_, err = db.Exec(grantConnectSQL)
	if err != nil {
		log.Fatal("Error granting connect: ", err)
	}

	/*_, err = db.Exec(grantUsageSQL)
	if err != nil {
		log.Fatal("Error granting usage: ", err)
	}*/

	_, err = db.Exec(grantSelectSQL)
	if err != nil {
		log.Fatal("Error granting select: ", err)
	}

	return nil
}

func CreateAgent(db *sql.DB, ID string, IPaddr string, akPub string, imaID string, state string) error {
	_, err := db.Exec("INSERT INTO agents(id, ipaddr_port, ak, whitelist_id, state) VALUES($1, $2, $3, $4, $5) RETURNING id", ID, IPaddr, akPub, imaID, state)
	if err != nil {
		return err
	}
	return nil
}

func ReadIP_Port(db *sql.DB, id string) (string, error) {
	var ipPort string
	err := db.QueryRow("SELECT ipaddr_port FROM agents WHERE id=$1", id).Scan(&ipPort)
	if err != nil {
		return "", err
	}
	return ipPort, nil
}

func ReadAK(db *sql.DB, id string) (string, error) {
	var ak string
	err := db.QueryRow("SELECT ak FROM agents WHERE id=$1", id).Scan(&ak)
	if err != nil {
		return "", err
	}
	return ak, nil
}

func ReadWhitelistId(db *sql.DB, id string) (string, error) {
	var imaID string
	err := db.QueryRow("SELECT whitelist_id FROM agents WHERE id=$1", id).Scan(&imaID)
	if err != nil {
		return "", err
	}
	return imaID, nil
}
func ReadState(db *sql.DB, id string) (string, error) {
	var state string
	err := db.QueryRow("SELECT state FROM agents WHERE id=$1", id).Scan(&state)
	if err != nil {
		return "", err
	}
	return state, nil
}

func UpdateIP_Port(db *sql.DB, id string, IPaddr string) error {
	_, err := db.Exec("UPDATE agents SET ipaddr_port=$1 WHERE id=$2", IPaddr, id)
	if err != nil {
		return err
	}
	return nil
}

func UpdateAK(db *sql.DB, id string, akPub string) error {
	_, err := db.Exec("UPDATE agents SET ak=$1 WHERE id=$2", akPub, id)
	if err != nil {
		return err
	}
	return nil
}
func UpdateWhitelistID(db *sql.DB, id string, whitelistID string) error {
	_, err := db.Exec("UPDATE agents SET whitelist_id=$1 WHERE id=$2", whitelistID, id)
	if err != nil {
		return err
	}
	return nil

}
func UpdateState(db *sql.DB, id string, state string) error {
	_, err := db.Exec("UPDATE agents SET state=$1 WHERE id=$2", state, id)
	if err != nil {
		return err
	}
	return nil

}
func DeleteDevice(db *sql.DB, id string) error {
	_, err := db.Exec("DELETE FROM agents WHERE id=$1", id)
	if err != nil {
		return err
	}
	return nil
}
