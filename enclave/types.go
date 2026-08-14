package main

import (
	"sync/atomic"
	"time"
)

type EnclaveServer struct {
	port       uint32
	keyManager *KeyManager

	// startTime anchors the uptime reported by appInfo.
	startTime time.Time

	// workers is the request worker pool: a buffered channel used as a
	// semaphore, so len is the number of requests in flight and cap the
	// ceiling. Sized in Start from ENCLAVE_MAX_WORKERS and held here so the
	// ping response can report pool occupancy.
	workers chan struct{}

	// connsAccepted counts every connection the vsock listener returned;
	// connsRejected counts the subset closed immediately because the worker
	// pool was full, so rejected is always a subset of accepted. Reported
	// cumulatively by appInfo, where an accepted count that stops advancing
	// while the host keeps dialing means the accept loop itself is no longer
	// turning.
	connsAccepted atomic.Uint64
	connsRejected atomic.Uint64
}

func NewEnclaveServer(port uint32) *EnclaveServer {
	return &EnclaveServer{port: port, startTime: time.Now()}
}
