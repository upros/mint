package mint

import (
	"crypto"
	"crypto/elliptic"
	"math/big"
)

func hashToBase(x []byte, hash crypto.Hash, crv elliptic.Curve) *big.Int {
	// Hash
	h := hash.New()
	h.Write(x)
	b := h.Sum(nil)

	// Truncate
	// XXX: Assumes hash size is bigger than modulus size
	p := crv.Params().P
	bits := uint(p.BitLen())
	bytes := bits >> 3
	bits = bits & 0x07
	b = b[:bytes]
	b[bytes-1] &= byte(0xff) >> (8 - bits)

	// Reduce
	n := big.NewInt(0).SetBytes(b)
	n = n.Mod(n, p)
	return n
}

func cmov(a, b *big.Int, c bool) *big.Int {
	if c {
		return a
	}

	return b
}

func map2curve_simple_swu2(t *big.Int, crv elliptic.Curve) (x, y *big.Int) {
	p := crv.Params().P
	a := big.NewInt(0).Sub(p, big.NewInt(3))
	b := crv.Params().B

	ainv := big.NewInt(0).ModInverse(a, p)

	p4 := big.NewInt(0)
	p4.Add(p, big.NewInt(1)).Rsh(p4, 2)

	one := big.NewInt(1)
	three := big.NewInt(3)

	alpha := big.NewInt(0)
	right := big.NewInt(0)
	left := big.NewInt(0)
	h2 := big.NewInt(0)
	h3 := big.NewInt(0)
	i2 := big.NewInt(0)
	i3 := big.NewInt(0)
	x2 := big.NewInt(0)
	x3 := big.NewInt(0)
	y1 := big.NewInt(0)
	y2 := big.NewInt(0)
	y1s := big.NewInt(0)

	alpha.Mul(t, t).Mod(alpha, p)                           // 2
	alpha.Sub(p, alpha)                                     // 3
	right.Mul(alpha, alpha).Add(right, alpha).Mod(right, p) // 4
	right.ModInverse(right, p)                              // 5
	right.Add(right, one).Mod(right, p)                     // 6
	left.Sub(p, b)                                          // 7
	left.Mul(left, ainv).Mod(left, p)                       // 8
	x2.Mul(left, right).Mod(x2, p)                          // 9
	x3.Mul(alpha, x2).Mod(x3, p)                            // 10
	h2.Exp(x2, three, p)                                    // 11
	i2.Mul(x2, a).Mod(i2, p)                                // 12
	i2.Add(i2, b).Mod(i2, p)                                // 13
	h2.Add(h2, i2).Mod(h2, p)                               // 14
	h3.Exp(x3, three, p)                                    // 15
	i3.Mul(x3, a).Mod(i3, p)                                // 16
	i3.Add(i3, b).Mod(i3, p)                                // 17
	h3.Add(h3, i3).Mod(h3, p)                               // 18
	y1.Exp(h2, p4, p)                                       // 19
	y2.Exp(h3, p4, p)                                       // 20
	e := (y1s.Mul(y1, y1).Mod(y1s, p).Cmp(h2) == 0)         // 21
	x = cmov(x2, x3, e)                                     // 22
	y = cmov(y1, y2, e)                                     // 23

	return
}

func HashToCurve(alpha []byte, hash crypto.Hash, crv elliptic.Curve) (x, y *big.Int) {
	alpha0 := append([]byte{0}, alpha...)
	t0 := hashToBase(alpha0, hash, crv)
	x0, y0 := map2curve_simple_swu2(t0, crv)

	alpha1 := append([]byte{1}, alpha...)
	t1 := hashToBase(alpha1, hash, crv)
	x1, y1 := map2curve_simple_swu2(t1, crv)

	return crv.Add(x0, y0, x1, y1)
}
