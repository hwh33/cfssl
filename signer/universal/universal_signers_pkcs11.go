// +build pkcs11

package universal

import (
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/pkcs11"
)

// pkcs11Signer looks for token, module, slot, and PIN configuration
// options in the root.
func pkcs11Signer(root *Root, policy *config.Signing) (signer.Signer, bool, error) {
	module := root.Config["pkcs11-module"]
	token := root.Config["pkcs11-token"]
	label := root.Config["pkcs11-label"]
	userPIN := root.Config["pkcs11-user-pin"]
	certFile := root.Config["cert-file"]

	if module == "" && token == "" && label == "" && userPIN == "" {
		return nil, false, nil
	}

	conf := pkcs11.Config{
		Module: module,
		Token:  token,
		Label:  label,
		PIN:    userPIN,
	}

	s, err := pkcs11.New(certFile, policy, &conf)
	return s, true, err
}

var localSignerList = []localSignerCheck{
	pkcs11Signer,
	fileBackedSigner,
}
