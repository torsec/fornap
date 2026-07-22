module verifier

go 1.23.3

toolchain go1.23.4

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/cobra v1.8.1
	github.com/spf13/pflag v1.0.5 // indirect
)

require github.com/google/go-tpm v0.9.1

require (
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/text v0.17.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	configR v1.0.0
	configV v1.0.0
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
	github.com/spf13/viper v1.19.0
	golang.org/x/sys v0.23.0 // indirect
)

replace configR => ./configR
replace configV => ./configV

require ima_verifier v1.0.0

replace ima_verifier => ./cmd/Verify/ima_verifier

require agent_db_handler v1.0.0

replace agent_db_handler => ./cmd/agent_db_handler

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.5.0 // indirect
	github.com/goccy/go-json v0.9.11 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/klauspost/compress v1.17.2 // indirect
	github.com/lestrrat-go/blackmagic v1.0.1 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.4 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/veraison/eat v0.0.0-20210331113810-3da8a4dd42ff // indirect
	github.com/veraison/go-cose v1.2.1 // indirect
	github.com/veraison/swid v1.1.1-0.20230911094910-8ffdd07a22ca
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/sync v0.8.0 // indirect
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-sev-guest v0.11.1 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.mongodb.org/mongo-driver v1.17.1
	golang.org/x/crypto v0.26.0 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
)

require first_quote_handler v1.0.0

replace first_quote_handler => ./cmd/Register/first_quote_handler

require tpm_db_handler v1.0.0

replace tpm_db_handler => ./cmd/Register/tpm_db_handler

require (
	github.com/lestrrat-go/jwx/v2 v2.0.8
	github.com/veraison/ear v1.1.2
	utils_verify v1.0.0
)

replace utils_verify => ./cmd/Verify/utils

require github.com/veraison/corim v1.1.2

require reference_handler v1.0.0

replace reference_handler => ./cmd/Verify/reference_handler
