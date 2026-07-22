# Reference Value Provider
installare golang, documentazione al link seguente https://go.dev/doc/install
aprire un terminale nella cartella "Reference Value Provider"
eseguire il programma tramite il comando "sudo go run reference.go"
il programma simula un Reference Value Provider accedendo al file di IMA dell'agent e mandando i measurements al Register nel formato "comid" richiesto da Veraison
il Register stampa l'ID della whitelist appena inserita, aggiornare quindi il file di config dell'agent

# Agent
installare docker, documentazione al link seguente https://docs.docker.com/engine/install/
aprire un terminale nella cartella "Agent" 
settare la modalità in cui dare inizio alle fasi di registrazione e attestazione tramite il file "config.yml" presente nella cartella config tramite le variabili "waitregister" e "waitverifier"
eseguire il programma tramite il comando "sudo docker compose up --build"

nel caso in cui l'agent venga messo in attesa di essere contattato dal Verifier, eseguire lo script "./agent_addr_provisioner.sh" che manda l'IP e la Porta dell'agent al Register
eseguire prima il comando "sudo chmod +x agent_addr_provisioner.sh" per rendere lo script eseguibile

le considerazioni fatte per "agent_addr_privisioner.sh" valgono anche per "deviceid.sh" nel caso in cui l'agent si mette in attesa per la fase di attestazione
in questo caso lo script invia il device ID di cui si deve far partire l'attestazione al Verifier, qujndi aggiornare il deviceID dello script

le stessa considerazioni valgono per il file "relying_party.sh" che simula un relying party che riceve i risultati di attestazione di un agent identificato dal DeviceID

