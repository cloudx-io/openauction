package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"
	"github.com/mdlayher/vsock"

	"github.com/cloudx-io/openauction/enclaveapi"
)

func (*EnclaveServer) initNSM() error {
	return nil
}

// getEnclaveAttester attempts to get the NSM attester, returns error if not available
func getEnclaveAttester() (EnclaveAttester, error) {
	handle, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return nil, fmt.Errorf("NSM not available: %w", err)
	}
	return handle, nil
}

func (s *EnclaveServer) Start() error {
	if err := s.initNSM(); err != nil {
		log.Printf("ERROR: NSM initialization failed: %v (continuing with mocks)", err)
	}

	keyManager, err := NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	s.keyManager = keyManager
	log.Printf("KeyManager initialized")

	tokenManager := NewTokenManager()
	s.tokenManager = tokenManager
	log.Printf("TokenManager initialized")

	tokenManager.StartExpirationCleanup(context.Background(), 10*time.Second, 1*time.Minute)
	log.Printf("Token expiration cleanup started (interval: 10s, max age: 1m)")

	listener, err := vsock.Listen(s.port, nil)
	if err != nil {
		return fmt.Errorf("failed to create vsock listener: %w", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("ERROR: Failed to close listener: %v", err)
		}
	}()

	log.Printf("INFO: TEE server listening on vsock port %d", s.port)

	maxWorkers, err := getRequiredEnvInt("ENCLAVE_MAX_WORKERS")
	if err != nil {
		return fmt.Errorf("failed to get max workers config: %w", err)
	}
	semaphore := make(chan struct{}, maxWorkers)

	log.Printf("INFO: Worker pool initialized with %d max concurrent workers", maxWorkers)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ERROR: Failed to accept vsock connection: %v", err)
			continue
		}

		// Acquire worker slot - immediate rejection if pool full
		select {
		case semaphore <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-semaphore }() // Release worker slot
				s.handleConnection(c)
			}(conn)
		default:
			log.Printf("INFO: No workers available, rejecting connection (pool full)")
			if err := conn.Close(); err != nil {
				log.Printf("ERROR: Failed to close rejected connection: %v", err)
			}
		}
	}
}

func (s *EnclaveServer) handleConnection(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: Panic recovered in handleConnection: %v", r)
		}
		if err := conn.Close(); err != nil {
			log.Printf("ERROR: Failed to close connection: %v", err)
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	var buf bytes.Buffer
	_, err := io.Copy(&buf, conn)
	if err != nil {
		log.Printf("ERROR: Failed to read request: %v", err)
		return
	}

	var baseReq struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(buf.Bytes(), &baseReq); err != nil {
		log.Printf("ERROR: Failed to decode base request: %v", err)
		return
	}

	log.Printf("INFO: Received request type: %s", baseReq.Type)

	var response any

	switch baseReq.Type {
	case "ping":
		response = map[string]any{
			"type":      "pong",
			"message":   "TEE server is healthy",
			"timestamp": time.Now().Unix(),
		}
		log.Printf("INFO: Responding to ping with pong")

	case "key_request":
		log.Printf("INFO: Processing key request")
		attester, err := getEnclaveAttester()
		if err != nil {
			response = map[string]any{
				"type":    "error",
				"message": fmt.Sprintf("Failed to initialize TEE attester: %v", err),
			}
			log.Printf("ERROR: Key request failed: %v", err)
		} else {
			keyResp, err := HandleKeyRequest(attester, s.keyManager, s.tokenManager)
			if err != nil {
				response = map[string]any{
					"type":    "error",
					"message": fmt.Sprintf("Key request failed: %v", err),
				}
				log.Printf("ERROR: Key request failed: %v", err)
			} else {
				response = keyResp
				log.Printf("INFO: Key request processed successfully")
			}
		}

	case "auction_request":
		var auctionReq enclaveapi.EnclaveAuctionRequest
		if err := json.Unmarshal(buf.Bytes(), &auctionReq); err != nil {
			log.Printf("ERROR: Failed to decode auction request: %v", err)
			response = map[string]any{
				"type":    "error",
				"message": fmt.Sprintf("Failed to decode auction request: %v", err),
			}
		} else {
			attester, err := getEnclaveAttester()
			if err != nil {
				response = map[string]any{
					"type":    "error",
					"message": fmt.Sprintf("Failed to initialize TEE attester: %v", err),
				}
				log.Printf("ERROR: Auction processing failed: %v", err)
			} else {
				response = ProcessAuction(attester, auctionReq, s.keyManager, s.tokenManager)
				log.Printf("INFO: Auction processed successfully with TEE attestation data")
			}
		}

	default:
		response = map[string]any{
			"type":    "error",
			"message": fmt.Sprintf("Unknown request type: %s", baseReq.Type),
		}
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		log.Printf("ERROR: Failed to encode response: %v", err)
	} else {
		log.Printf("INFO: Successfully sent response for %s", baseReq.Type)
	}
}

// Helper function for required environment variable parsing
func getRequiredEnvInt(key string) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return 0, fmt.Errorf("required environment variable %s is not set", key)
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s: %s (must be a valid integer)", key, value)
	}

	log.Printf("INFO: Using %s=%d from environment", key, intValue)
	return intValue, nil
}

func main() {
	server := NewEnclaveServer(5000)
	log.Fatal(server.Start())
}
