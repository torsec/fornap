# Reference Value Provider
install golang, documentation at the following link https://go.dev/doc/install
open a terminal in the "Reference Value Provider" folder
run the program using the command "sudo go run reference.go"
the program simulates a Reference Value Provider by accessing the agent's IMA file and sending measurements to the Register in the "comid" format required by Veraison
the Register prints the ID of the newly inserted whitelist; then update the agent's config file

# Agent
install docker, documentation at the following link https://docs.docker.com/engine/install/
open a terminal in the "Agent" folder
set the mode to start the registration and attestation phases via the "config.yml" file in the config folder using the variables "waitregister" and "waitverifier"
run the program using the command "sudo docker compose up --build"

if the agent is set to wait to be contacted by the Verifier, run the script "./agent_addr_provisioner.sh" which sends the agent's IP and Port to the Register
first run the command "sudo chmod +x agent_addr_provisioner.sh" to make the script executable

the considerations made for "agent_addr_provisioner.sh" also apply to "deviceid.sh" if the agent waits for the attestation phase
in this case, the script sends the device ID for which attestation should start to the Verifier, so update the script's deviceID

the same considerations apply to the "relying_party.sh" file, which simulates a relying party receiving attestation results for an agent identified by the DeviceID
