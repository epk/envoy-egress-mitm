package types

type Certificate struct {
	SNI string `json:"sni,omitempty"`

	Key  []byte `json:"key,omitempty"`
	Cert []byte `json:"cert,omitempty"`

	CAName string `json:"ca_name,omitempty"`
	CA     []byte `json:"ca,omitempty"`
}
