package configR

type Configurations struct {
	PostgreServer     ServerConfigurations
	PostgresDatabase  DatabaseConfigurations
	Mongodb           MongodbConfigurations
	RegisterNet       RegisterNetConfigurations
	FirstQuote        FirstQuoteConfigurations
	CreateJWTKeys     JWTKeyConfigurations
	JWTKeyPath        JWTKeyPathConfigurations
	RegisterIdentity  RegisterIdentityConfigurations
	StartAttestation  StartAttestationConfigurations
	VerifierNet       VerifierNetConfigurations
	StartRegistration StartRegistrationConfigurations
}

type ServerConfigurations struct {
	Ip   string
	Port int
}

type DatabaseConfigurations struct {
	DBName             string
	DBUser             string
	DBPassword         string
	DBUserVerifier     string
	DBPasswordVerifier string
}

type MongodbConfigurations struct {
	MongoUser             string
	MongoPassword         string
	MongoUserVerifier     string
	MongoPasswordVerifier string
	//MongoURL      string
	MongoIP   string
	MongoPort int
}

type RegisterNetConfigurations struct {
	Ip   string
	Port int
}

type FirstQuoteConfigurations struct {
	HashAlgo string
}
type JWTKeyConfigurations struct {
	Create bool
}
type JWTKeyPathConfigurations struct {
	RegisterPath string
	VerifierPath string
}

type RegisterIdentityConfigurations struct {
	Build     string
	Developer string
}

type StartAttestationConfigurations struct {
	Start bool
	Port  int
}

type StartRegistrationConfigurations struct {
	Start bool
}

type VerifierNetConfigurations struct {
	Ip   string
	Port int
}
