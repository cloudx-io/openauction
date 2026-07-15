package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cloudx-io/openauction/enclaveapi"
)

// Key rotation is tuned entirely at compile time. These are deliberately consts
// rather than env/vsock configuration: changing the rotation cadence or the
// retention window is a code change plus a rebuild, which keeps the knobs inside
// the attested image rather than in mutable runtime configuration.
const (
	// keyRotationInterval is how often a fresh keypair (a new epoch) is minted.
	keyRotationInterval = 1 * time.Minute

	// keyRetention is how long an epoch's private key (and its ciphertext dedup
	// set) is kept alive after the epoch stops being the current one. A bid
	// sealed to a slightly-older public key still decrypts within this window;
	// once an epoch ages out, its key material and dedup set are dropped.
	keyRetention = 5 * time.Minute
)

// keyEpoch is a single generation of the enclave's E2EE keypair.
//
// Each epoch owns:
//   - an RSA keypair used to decrypt bids sealed to that epoch's public key,
//   - a key attestation generated exactly once at epoch creation and served
//     verbatim on every key request while the epoch is current (no per-request
//     Attest() call), and
//   - a ciphertext dedup set scoped to this epoch. When the epoch ages out, the
//     private key and the dedup set are released together, which bounds memory
//     and ties replay protection to key lifetime rather than a wall clock.
type keyEpoch struct {
	privateKey *rsa.PrivateKey // Keep private - sensitive!
	PublicKey  *rsa.PublicKey

	createdAt time.Time

	// cachedAttestation is the gzip-compressed COSE key attestation for this
	// epoch's public key, computed once at creation.
	cachedAttestation enclaveapi.AttestationCOSEGzip
	// cachedAttestationUs is the wall-clock time spent in the one-time Attest()
	// call for this epoch, in microseconds. Reported for operational visibility.
	cachedAttestationUs *float64

	// dedup holds the ciphertext fingerprints already seen for bids that
	// decrypted under this epoch's key. It lives and dies with the epoch.
	dedup ciphertextDedup
}

// KeyManager manages a small ring of recent key epochs for E2EE.
//
// The newest epoch is "current" and is what key requests advertise. Older
// epochs are retained (up to keyRetention) so that bids sealed to a
// just-superseded public key still decrypt. Trial decryption across live epochs
// (see DecryptBid) resolves which epoch a given bid belongs to without any
// key-id on the wire.
type KeyManager struct {
	mu     sync.RWMutex
	epochs []*keyEpoch // ordered oldest -> newest; last element is current
}

// NewKeyManager creates a KeyManager seeded with a single current epoch whose
// key attestation is generated up front. The attester is required so that the
// current epoch always has a cached attestation ready to serve.
func NewKeyManager(attester EnclaveAttester) (*KeyManager, error) {
	km := &KeyManager{}
	if _, err := km.addEpoch(attester); err != nil {
		return nil, err
	}
	return km, nil
}

// newKeyEpoch generates a fresh keypair and pre-computes its key attestation.
func newKeyEpoch(attester EnclaveAttester) (*keyEpoch, error) {
	privateKey, err := GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	coseAttestation, attestationUs, err := GenerateKeyAttestation(attester, &privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key attestation: %w", err)
	}

	attestationGzip, err := coseAttestation.CompressGzip()
	if err != nil {
		return nil, fmt.Errorf("failed to compress attestation: %w", err)
	}

	return &keyEpoch{
		privateKey:          privateKey,
		PublicKey:           &privateKey.PublicKey,
		createdAt:           time.Now(),
		cachedAttestation:   attestationGzip,
		cachedAttestationUs: attestationUs,
	}, nil
}

// addEpoch creates a new current epoch and evicts any epochs older than the
// retention window. It returns the newly created epoch.
func (km *KeyManager) addEpoch(attester EnclaveAttester) (*keyEpoch, error) {
	epoch, err := newKeyEpoch(attester)
	if err != nil {
		return nil, err
	}

	km.mu.Lock()
	defer km.mu.Unlock()
	km.epochs = append(km.epochs, epoch)
	km.evictExpiredLocked(epoch.createdAt)
	return epoch, nil
}

// evictExpiredLocked drops epochs older than keyRetention. The current (newest)
// epoch is always retained regardless of age so the enclave can always serve a
// key. Callers must hold km.mu.
func (km *KeyManager) evictExpiredLocked(now time.Time) {
	if len(km.epochs) <= 1 {
		return
	}
	// The last element is the current epoch and is never evicted here.
	kept := km.epochs[:0:0]
	for i, epoch := range km.epochs {
		isCurrent := i == len(km.epochs)-1
		if isCurrent || now.Sub(epoch.createdAt) <= keyRetention {
			kept = append(kept, epoch)
		}
	}
	km.epochs = kept
}

// liveEpochs returns a snapshot of the currently retained epochs, newest first.
// Trying the newest epoch first makes the common case (a bid sealed to the
// freshly advertised key) the fastest to resolve.
func (km *KeyManager) liveEpochs() []*keyEpoch {
	km.mu.RLock()
	defer km.mu.RUnlock()
	snapshot := make([]*keyEpoch, len(km.epochs))
	for i, epoch := range km.epochs {
		snapshot[len(km.epochs)-1-i] = epoch
	}
	return snapshot
}

// currentEpoch returns the newest epoch, or nil if none exist.
func (km *KeyManager) currentEpoch() *keyEpoch {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if len(km.epochs) == 0 {
		return nil
	}
	return km.epochs[len(km.epochs)-1]
}

// StartRotation rotates the current epoch on a fixed interval and evicts expired
// epochs as it goes. It runs until the context is canceled. Rotation failures
// (e.g. a transient attestation error) are logged and retried on the next tick;
// the existing epochs keep serving in the meantime.
func (km *KeyManager) StartRotation(ctx context.Context, attester EnclaveAttester) {
	go func() {
		ticker := time.NewTicker(keyRotationInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("Key rotation: stopping due to context cancellation")
				return
			case <-ticker.C:
				if _, err := km.addEpoch(attester); err != nil {
					log.Printf("ERROR: Key rotation failed, keeping existing epochs: %v", err)
					continue
				}
				log.Printf("Key rotation: minted new epoch (live epochs: %d)", km.epochCount())
			}
		}
	}()
}

// epochCount returns the number of currently retained epochs (for monitoring).
func (km *KeyManager) epochCount() int {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return len(km.epochs)
}

// publicKeyPEM returns an epoch's public key in PEM format.
func (e *keyEpoch) publicKeyPEM() (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(e.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// DecryptBid attempts to decrypt an encrypted bid against every live epoch and
// returns the plaintext plus the epoch that decrypted it. Because RSA-OAEP
// padding and the AES-GCM authentication tag both fail closed, only the epoch
// whose key actually sealed the bid will succeed — this resolves the epoch
// without any key-id on the wire. The returned epoch handle is used to scope the
// ciphertext dedup set.
func (km *KeyManager) DecryptBid(enc *enclaveapi.EncryptedBidPrice, hashAlg HashAlgorithm) ([]byte, *keyEpoch, error) {
	epochs := km.liveEpochs()
	if len(epochs) == 0 {
		return nil, nil, fmt.Errorf("no key epochs available")
	}

	var lastErr error
	for _, epoch := range epochs {
		plaintext, err := DecryptHybrid(
			enc.AESKeyEncrypted,
			enc.EncryptedPayload,
			enc.Nonce,
			epoch.privateKey,
			hashAlg,
		)
		if err == nil {
			return plaintext, epoch, nil
		}
		lastErr = err
	}

	return nil, nil, fmt.Errorf("failed to decrypt with any live key epoch: %w", lastErr)
}

// HandleKeyRequest returns the current epoch's public key together with its
// pre-computed key attestation. This path performs no Attest() call: the
// attestation was generated once when the epoch was minted and is served from
// cache, so key requests no longer contend on the serialized attestation
// operation.
func HandleKeyRequest(keyManager *KeyManager) (*enclaveapi.KeyResponse, error) {
	epoch := keyManager.currentEpoch()
	if epoch == nil {
		return nil, fmt.Errorf("no key epoch available")
	}

	publicKeyPEM, err := epoch.publicKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to export public key: %w", err)
	}

	return &enclaveapi.KeyResponse{
		KeyWithAttestation: enclaveapi.KeyWithAttestation{
			PublicKey:   publicKeyPEM,
			Attestation: epoch.cachedAttestation,
		},
		Type:          "key_response",
		AttestationUs: epoch.cachedAttestationUs,
	}, nil
}
