package schnorr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
)

var (
	one          = big.NewInt(1)
	challengeTag = sha256.Sum256([]byte("BIP0340/challenge"))
	// BIP340Challenge is sha256("BIP0340/challenge")
	BIP340Challenge = "7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37ctag"
	//secp256k1.N
	CurveGroupOrder, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
)

// GuessPrivateKey tries to guess the private used in the creation of two
// two Schnorr signatures. The nonce has to be reused in both signatures in order
// to be able to guess the private key.
// All parameters are expected to be hex encoded.
func GuessPrivateKey(publicKey, msg1, sig1, msg2, sig2 string) (string, error) {
	pk, err := hexToInt(publicKey)
	if err != nil {
		return "", err
	}
	m1, err := hexToInt(msg1)
	if err != nil {
		return "", err
	}
	s1, err := hexToInt(sig1)
	if err != nil {
		return "", err
	}
	m2, err := hexToInt(msg2)
	if err != nil {
		return "", err
	}
	s2, err := hexToInt(sig2)
	if err != nil {
		return "", err
	}
	//p :private key
	//P=pG :public key
	//m :message
	//r :random nonce
	//R=rG :nonce commitment
	//G :generator //CurveGroupOrder

	// the first 256 bits of the signatures are R
	R := new(big.Int).Rsh(s2, 256)
	R2 := new(big.Int).Lsh(R, 256)
	resps1 := new(big.Int).Sub(s1, R2)
	resps2 := new(big.Int).Sub(s2, R2)

	e1hash := challengeHash(R, pk, m1)
	e2hash := challengeHash(R, pk, m2)

	e1 := new(big.Int).Mod(new(big.Int).SetBytes(e1hash), CurveGroupOrder)
	e2 := new(big.Int).Mod(new(big.Int).SetBytes(e2hash), CurveGroupOrder)

	i := new(big.Int).Mod(new(big.Int).Sub(resps1, resps2), CurveGroupOrder)
	j := new(big.Int).Mod(new(big.Int).Sub(e1, e2), CurveGroupOrder)
	gcd, x, _ := eea(j, CurveGroupOrder)
	if gcd.Cmp(one) != 0 {
		return "", errors.New("GCD of divisor mod n is not 1. Modular inverse is not defined.")
	}

	p := new(big.Int).Mod(new(big.Int).Mul(i, new(big.Int).Mod(x, CurveGroupOrder)), CurveGroupOrder)
	return string(p.Bytes()), nil
}

func challengeHash(R, P, m *big.Int) []byte {
	var res []byte
	res = append(res, R.Bytes()...)
	res = append(res, P.Bytes()...)
	res = append(res, m.Bytes()...)
	return taggedHash(BIP340Challenge, res)
}

func hexToInt(s string) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	res := new(big.Int).SetBytes(b)
	return res, nil
}

// return (g, x, y) such that a*x + b*y = g = gcd(a, b)
func eea(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if len(a.Bits()) == 0 {
		return b, new(big.Int), one
	}
	b_div_a := new(big.Int).Div(b, a)
	b_mod_a := new(big.Int).Mod(b, a)
	g, x, y := eea(b_mod_a, a)
	return g, new(big.Int).Sub(y, new(big.Int).Mul(b_div_a, x)), x
}

func taggedHash(tag string, msg []byte) []byte {
	tagHash, _ := hex.DecodeString(tag)
	tagLen := len(tagHash)
	msgLen := len(msg)
	m := make([]byte, tagLen*2+msgLen)
	copy(m[:tagLen], tagHash)
	copy(m[tagLen:tagLen*2], tagHash)
	copy(m[tagLen*2:], msg)
	h := sha256.Sum256(m)
	return h[:]
}
