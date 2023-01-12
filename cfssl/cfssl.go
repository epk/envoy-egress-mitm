package cfssl

import (
	_ "embed"
)

//go:embed combined.crt
var CA []byte
