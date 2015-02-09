// +build !pkcs11

package universal

// Without any build flags, the only local signer that should be
// activated is the file-backed local signer.
var localSignerList = []localSignerCheck{
	fileBackedSigner,
}
