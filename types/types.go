package types

type Certificate struct {
	SNI string `json:"sni,omitempty"`

	Key  []byte `json:"key,omitempty"`
	Cert []byte `json:"cert,omitempty"`
}
