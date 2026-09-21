# fornap

Remote attestation framework based on TPM 2.0 and Linux Integrity Measurement Architecture (IMA), using Veraison CoMID reference values.

## Architecture

- **Verifier Side (`Verifier_Side/Verifier_Box`)**
  - **Register**: Handles agent device registration, TPM credential activation (EK/AK), and reference value ingestion into MongoDB. Backed by PostgreSQL for device records.
  - **Verifier**: Verifies TPM quotes and runtime IMA measurements against reference values, and serves attestation results to relying parties.
  - **Databases**: PostgreSQL (device state) and MongoDB (reference values / whitelists).
- **Agent Side (`Agent_Side`)**
  - **Reference Value Provider (`Reference_Value_Provider`)**: Parses `/sys/kernel/security/integrity/ima/ascii_runtime_measurements` and submits baseline measurements to the Register in Veraison CoMID format.
  - **Agent (`Agent`)**: Interacts with the local TPM device (`/dev/tpm0`), creates key hierarchies, completes credential activation with the Register, and produces attestation evidence for the Verifier.

## Prerequisites

- Linux host with TPM 2.0 (`/dev/tpm0`) and IMA enabled
- Docker and Docker Compose
- Go 1.23+ (for standalone Reference Value Provider)

## Getting Started

### 1. Start Verifier Infrastructure

1. Inspect configuration files:
   - `Verifier_Side/Verifier_Box/configR/config.yml` (Register settings, DB credentials, network)
   - `Verifier_Side/Verifier_Box/configV/config.yml` (Verifier settings, network)
2. Build and start services:
   ```bash
   cd Verifier_Side/Verifier_Box
   docker compose up --build
   ```
   This starts PostgreSQL, MongoDB, Register (port 8080), and Verifier (port 8081).

### 2. Provision Reference Values

On the reference machine:
1. Ensure the Register URL in `Agent_Side/Reference_Value_Provider/reference.go` points to your Register instance.
2. Run the provider with root privileges:
   ```bash
   cd Agent_Side/Reference_Value_Provider
   sudo go run reference.go
   ```
3. Copy the returned whitelist ID printed by the Register.

### 3. Run the Agent

1. Update `Agent_Side/Agent/config/config.yml`:
   - Set `whitelistid.id` to the ID obtained in step 2.
   - Configure network settings (`agentnet`, `registernet`, `verifiernet`).
   - Configure operational modes (`waitregister`, `waitverifier`).
2. Build and run the Agent container:
   ```bash
   cd Agent_Side/Agent
   sudo docker compose up --build
   ```

### 4. Helper Scripts

Located in `Agent_Side/`:
- `agent_addr_provisioner.sh`: Sends the agent's IP and port to the Register when running in waiting mode.
- `deviceid.sh`: Sends the target device ID to the Verifier to initiate attestation.
- `relying_party.sh`: Queries attestation verification results for a given device ID from the Verifier.
