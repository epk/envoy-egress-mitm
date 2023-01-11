//go:build tools
// +build tools

package tools

import (
	_ "github.com/cloudflare/cfssl/cmd/cfssl"
	_ "github.com/cloudflare/cfssl/cmd/cfssljson"
)
