package configV

type Configurations struct {
	PostgreServer     ServerConfigurations
	PostgresDatabase  DatabaseConfigurations
	Mongodb           MongodbConfigurations
	VerifierNet       VerifierNetConfigurations
	RegisterNet       RegisterNetConfigurations
	CreateJWTKeys     JWTKeyConfigurations
	JWTKeyPath        JWTKeyPathConfigurations
	VerifierIdentity  VerifierIdentityConfigurations
	StartAttestation  StartAttestationConfigurations
	AttestationPeriod AttestationPeriodConfigurations
}

type ServerConfigurations struct {
	Ip   string
	Port int
}

type DatabaseConfigurations struct {
	DBName     string
	DBUser     string
	DBPassword string
}

type MongodbConfigurations struct {
	MongoUser     string
	MongoPassword string
	//MongoURL      string
	MongoIP   string
	MongoPort int
}

type VerifierNetConfigurations struct {
	Ip   string
	Port int
}

type JWTKeyConfigurations struct {
	Create bool
}
type JWTKeyPathConfigurations struct {
	RegisterPath string
	VerifierPath string
}
type VerifierIdentityConfigurations struct {
	Build     string
	Developer string
}
type StartAttestationConfigurations struct {
	Port  int
	Start bool
}

type AttestationPeriodConfigurations struct {
	Seconds int
}

type RegisterNetConfigurations struct {
	Ip   string
	Port int
}
