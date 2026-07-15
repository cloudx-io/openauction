package main

type EnclaveServer struct {
	port       uint32
	keyManager *KeyManager
}

func NewEnclaveServer(port uint32) *EnclaveServer {
	return &EnclaveServer{port: port}
}
