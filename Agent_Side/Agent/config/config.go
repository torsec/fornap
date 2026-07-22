package config

type Configurations struct {
	AgentNet AgentNetConfigurations

	RegisterNet  RegisterNetConfigurations
	WaitRegister WaitRegisterConfigurations
	KeyTemplates KeyTemplatesConfigurations
	WhitelistID  WhitelistIdConfigurations

	VerifierNet       VerifierNetConfigurations
	AttestationPeriod PeriodConfigurations
	WaitVerifier      WaitVerifierConfigurations
}

type AgentNetConfigurations struct {
	Ip           string
	RegisterPort int
	AttesterPort int
}

type RegisterNetConfigurations struct {
	Ip   string
	Port int
}

type WaitRegisterConfigurations struct {
	Wait bool
}

type WaitVerifierConfigurations struct {
	Wait bool
}

type KeyTemplatesConfigurations struct {
	EKTemplate  string
	SRKTemplate string
	AKTemplate  string
}

type WhitelistIdConfigurations struct {
	ID string
}

type VerifierNetConfigurations struct {
	Ip   string
	Port int
}

type PeriodConfigurations struct {
	Seconds int
}
