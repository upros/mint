package mint

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type DHOPRFRequest struct {
	Ax, Ay *big.Int
	Alpha  []byte
}

type DHOPRFResponse struct {
	Bx, By *big.Int
	Vx, Vy *big.Int
	Beta   []byte
	vU     []byte
}

type DHOPRFInput struct {
	X   []byte `tls:"head=1"`
	Vx  []byte `tls:"head=1"`
	Vy  []byte `tls:"head=1"`
	KHx []byte `tls:"head=1"`
	KHy []byte `tls:"head=1"`
}

type DHOPRF struct {
	hash crypto.Hash
	crv  elliptic.Curve

	// Client
	x        []byte
	r        []byte
	hx, hy   *big.Int
	khx, khy *big.Int

	// Server
	k      []byte
	vx, vy *big.Int
}

func NewDHOPRFClient(hash crypto.Hash, crv elliptic.Curve) *DHOPRF {
	return &DHOPRF{
		hash: hash,
		crv:  crv,
	}
}

func NewDHOPRFServer(hash crypto.Hash, crv elliptic.Curve) (*DHOPRF, error) {
	k, Vx, Vy, err := elliptic.GenerateKey(crv, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &DHOPRF{
		hash: hash,
		crv:  crv,
		k:    k,
		vx:   Vx,
		vy:   Vy,
	}, nil
}

func (prf *DHOPRF) CreateRequest(x []byte) (*DHOPRFRequest, error) {
	r, Rx, Ry, err := elliptic.GenerateKey(prf.crv, rand.Reader)
	if err != nil {
		return nil, err
	}

	prf.r = r
	prf.hx, prf.hy = HashToCurve(x, prf.hash, prf.crv)
	Ax, Ay := prf.crv.Add(prf.hx, prf.hy, Rx, Ry)
	request := DHOPRFRequest{
		Ax:    Ax,
		Ay:    Ay,
		Alpha: elliptic.Marshal(prf.crv, Ax, Ay),
	}
	return &request, nil
}

func (prf *DHOPRF) HandleRequest(req *DHOPRFRequest) *DHOPRFResponse {
	if len(req.Alpha) != 0 {
		req.Ax, req.Ay = elliptic.Unmarshal(prf.crv, req.Alpha)
	}
	Bx, By := prf.crv.ScalarMult(req.Ax, req.Ay, prf.k)
	response := DHOPRFResponse{
		Bx:   Bx,
		By:   By,
		Vx:   prf.vx,
		Vy:   prf.vy,
		Beta: elliptic.Marshal(prf.crv, Bx, By),
		vU:   elliptic.Marshal(prf.crv, prf.vx, prf.vy),
	}
	return &response
}

func (prf *DHOPRF) HandleResponse(resp *DHOPRFResponse) []byte {
	if len(resp.Beta) != 0 {
		resp.Bx, resp.By = elliptic.Unmarshal(prf.crv, resp.Beta)
	}
	if len(resp.vU) != 0 {
		resp.Vx, resp.Vy = elliptic.Unmarshal(prf.crv, resp.vU)
	}
	ri := big.NewInt(0)
	ri.SetBytes(prf.r).Sub(prf.crv.Params().N, ri)

	riVx, riVy := prf.crv.ScalarMult(resp.Vx, resp.Vy, ri.Bytes())
	prf.khx, prf.khy = prf.crv.Add(resp.Bx, resp.By, riVx, riVy)

	// TODO: Replace with this a proper structure
	h := prf.hash.New()
	h.Write(prf.x)
	h.Write(resp.Vx.Bytes())
	h.Write(resp.Vy.Bytes())
	h.Write(prf.khx.Bytes())
	h.Write(prf.khy.Bytes())

	return h.Sum(nil)
}
