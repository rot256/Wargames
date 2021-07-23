package main

import (
	"crypto-tiramisu/pb"
	"fmt"
)

const serverCurveId = pb.EcdhKey_SECP224R1

func main() {
	fmt.Println("vim-go")

	D := server.key.D.Bytes()

	sharedX, _ := server.key.ScalarMult(X, Y, D)
}
