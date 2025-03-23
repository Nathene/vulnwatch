package common

type Vulnerability struct {
	Name      string
	Severity  string
	Directory string
}

type Vulnerabilities struct {
	Vulnerabilities []Vulnerability
}

func NewVulnerabilities() *Vulnerabilities {
	return &Vulnerabilities{}
}

func (v *Vulnerabilities) Add(vulnerability Vulnerability) {
	v.Vulnerabilities = append(v.Vulnerabilities, vulnerability)
}

func (v *Vulnerabilities) Get() []Vulnerability {
	return v.Vulnerabilities
}
