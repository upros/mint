package mint

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"testing"
)

func TestOPRF(t *testing.T) {

	hash := crypto.SHA256
	crv := elliptic.P256()
	x := []byte{1, 2, 3, 5, 6}

	// client:  DHOPRF        struct

	client := NewDHOPRFClient(hash, crv)

	// server:  DHOPRF        struct
	//   server.k:       kU
	//   server.vx/vy:   vU   (= g^kU)

	server, _ := NewDHOPRFServer(hash, crv)

	// 1. REGISTER PASSWORD

	// regPwdRequest: DHOPRFRequest struct
	//    client.r:      r
	//    client.hx/hy:  H'(x)
	//    regPwdReq.Az/Ay: alpha

	regPwdRequest, _ := client.CreateRequest(x)

	// response: DHOPRFResponse struct
	//   response.Bx/By:    beta
	//   response.Vx/Vy:    vU

	regPwdResponse := server.HandleRequest(regPwdRequest)

	// result: []byte

	regPwdRwdU := client.HandleResponse(regPwdResponse)

	// 2. LOGIN
	// Create a new request that will use a new random 'r' value

	loginRequest, _ := client.CreateRequest(x)
	loginResponse := server.HandleRequest(loginRequest)
	loginRwdU := client.HandleResponse(loginResponse)

	assertTrue(t, bytes.Compare(regPwdRwdU, loginRwdU) == 0, "RwdU mismatch")

	// 3. LOGIN with wrong password
	xx := []byte{1, 2, 3, 5, 6, 7}
	badRequest, _ := client.CreateRequest(xx)
	badResponse := server.HandleRequest(badRequest)
	badRwdU := client.HandleResponse(badResponse)

	assertTrue(t, bytes.Compare(regPwdRwdU, badRwdU) != 0, "Wrong password worked")
}
