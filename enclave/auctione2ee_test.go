package main

import (
	"encoding/json"
	"testing"

	"github.com/peterldowns/testy/assert"

	"github.com/cloudx-io/openauction/core"
	"github.com/cloudx-io/openauction/enclaveapi"
)

func TestDecryptBids_NoEncryptedData(t *testing.T) {
	km, _ := NewKeyManager()

	encBids := []enclaveapi.EncryptedCoreBid{
		{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 2.50}},
		{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder2", Price: 3.00}},
	}

	decryptedData, _, errors := decryptAllBids(encBids, km)
	assert.Equal(t, 0, len(errors))

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 2, len(finalBids))
	assert.Equal(t, 2.50, finalBids[0].Price)
}

func TestDecryptBids_MixedEncryptedUnencrypted(t *testing.T) {
	km, _ := NewKeyManager()

	payload := map[string]any{
		"price": 4.25,
	}
	plaintextBytes, _ := json.Marshal(payload)
	result, _ := EncryptHybridWithHash(plaintextBytes, km.PublicKey, HashAlgorithmSHA256)

	encBids := []enclaveapi.EncryptedCoreBid{
		{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 2.50}},
		{
			CoreBid: core.CoreBid{
				ID:     "bid2",
				Bidder: "bidder2",
			},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  result.EncryptedAESKey,
				EncryptedPayload: result.EncryptedPayload,
				Nonce:            result.Nonce,
			},
		},
		{CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder3", Price: 3.75}},
	}

	decryptedData, _, errors := decryptAllBids(encBids, km)
	assert.Equal(t, 0, len(errors))

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 3, len(finalBids))
	assert.Equal(t, 2.50, finalBids[0].Price)
	assert.Equal(t, 4.25, finalBids[1].Price)
	assert.Equal(t, 3.75, finalBids[2].Price)
}

func TestDecryptBids_InvalidEncryptedData(t *testing.T) {
	km, _ := NewKeyManager()

	encBids := []enclaveapi.EncryptedCoreBid{
		{
			CoreBid: core.CoreBid{
				ID:     "bid1",
				Bidder: "bidder1",
			},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  "invalid-base64",
				EncryptedPayload: "invalid-base64",
				Nonce:            "invalid-base64",
			},
		},
	}

	decryptedData, _, errors := decryptAllBids(encBids, km)
	assert.Equal(t, 1, len(errors))

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 0, len(finalBids)) // Excluded
}

func TestDecryptBids_InvalidPrice(t *testing.T) {
	km, _ := NewKeyManager()

	payload := map[string]any{
		"price": -1.50,
	}
	plaintextBytes, _ := json.Marshal(payload)
	result, _ := EncryptHybridWithHash(plaintextBytes, km.PublicKey, HashAlgorithmSHA256)

	encBids := []enclaveapi.EncryptedCoreBid{
		{
			CoreBid: core.CoreBid{
				ID:     "bid1",
				Bidder: "bidder1",
			},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  result.EncryptedAESKey,
				EncryptedPayload: result.EncryptedPayload,
				Nonce:            result.Nonce,
			},
		},
	}

	decryptedData, _, errors := decryptAllBids(encBids, km)
	assert.Equal(t, 0, len(errors)) // Decryption succeeds

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 0, len(finalBids)) // Excluded due to invalid price in filtering stage
}

func TestDecryptBids_NilKeyManager(t *testing.T) {
	encBids := []enclaveapi.EncryptedCoreBid{
		{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 2.50}},
	}

	decryptedData, excludedBids, errors := decryptAllBids(encBids, nil)
	assert.Equal(t, 0, len(errors))
	assert.Equal(t, 0, len(excludedBids))

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 1, len(finalBids))
}

func TestDecryptBids_WrongKey(t *testing.T) {
	km1, _ := NewKeyManager()
	km2, _ := NewKeyManager()

	payload := map[string]any{
		"price": 2.50,
	}
	plaintextBytes, _ := json.Marshal(payload)
	result, _ := EncryptHybridWithHash(plaintextBytes, km1.PublicKey, HashAlgorithmSHA256)

	encBids := []enclaveapi.EncryptedCoreBid{
		{
			CoreBid: core.CoreBid{
				ID:     "bid1",
				Bidder: "bidder1",
			},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  result.EncryptedAESKey,
				EncryptedPayload: result.EncryptedPayload,
				Nonce:            result.Nonce,
			},
		},
	}

	decryptedData, excludedBids, errors := decryptAllBids(encBids, km2)
	assert.Equal(t, 1, len(errors))
	assert.Equal(t, 1, len(excludedBids)) // Should be excluded
	assert.Equal(t, "bid1", excludedBids[0].BidID)
	assert.Equal(t, "bidder1", excludedBids[0].Bidder)

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 0, len(finalBids)) // Should fail
}

func TestDecryptBids_BothEncryptedAndUnencryptedPrice(t *testing.T) {
	km, _ := NewKeyManager()

	// Create encrypted price payload
	payload := map[string]any{
		"price": 7.25, // This should take precedence
	}
	plaintextBytes, _ := json.Marshal(payload)
	result, _ := EncryptHybridWithHash(plaintextBytes, km.PublicKey, HashAlgorithmSHA256)

	encBids := []enclaveapi.EncryptedCoreBid{
		{
			CoreBid: core.CoreBid{
				ID:     "bid1",
				Bidder: "bidder1",
				Price:  2.50, // This should be ignored in favor of encrypted price
			},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  result.EncryptedAESKey,
				EncryptedPayload: result.EncryptedPayload,
				Nonce:            result.Nonce,
			},
		},
	}

	decryptedData, excludedBids, errors := decryptAllBids(encBids, km)
	// Should successfully decrypt
	assert.Equal(t, 0, len(errors))
	assert.Equal(t, 0, len(excludedBids))

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 1, len(finalBids))

	bid := finalBids[0]
	assert.Equal(t, "bid1", bid.ID)
	assert.Equal(t, "bidder1", bid.Bidder)
	assert.Equal(t, 7.25, bid.Price) // Should use encrypted price, not CoreBid.Price
}

func TestDecryptBids_HashAlgorithms(t *testing.T) {
	km, _ := NewKeyManager()

	tests := []struct {
		name            string
		encryptHashAlg  HashAlgorithm
		declaredHashAlg string
		expectedPrice   float64
	}{
		{
			name:            "SHA-256 explicit",
			encryptHashAlg:  HashAlgorithmSHA256,
			declaredHashAlg: "SHA-256",
			expectedPrice:   6.50,
		},
		{
			name:            "SHA-1 legacy",
			encryptHashAlg:  HashAlgorithmSHA1,
			declaredHashAlg: "SHA-1",
			expectedPrice:   8.75,
		},
		{
			name:            "default to SHA-256",
			encryptHashAlg:  HashAlgorithmSHA256,
			declaredHashAlg: "",
			expectedPrice:   4.00,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{
				"price": tt.expectedPrice,
			}
			plaintextBytes, _ := json.Marshal(payload)
			result, _ := EncryptHybridWithHash(plaintextBytes, km.PublicKey, tt.encryptHashAlg)

			encBids := []enclaveapi.EncryptedCoreBid{
				{
					CoreBid: core.CoreBid{
						ID:     "bid1",
						Bidder: "bidder1",
					},
					EncryptedPrice: &enclaveapi.EncryptedBidPrice{
						AESKeyEncrypted:  result.EncryptedAESKey,
						EncryptedPayload: result.EncryptedPayload,
						Nonce:            result.Nonce,
						HashAlgorithm:    tt.declaredHashAlg,
					},
				},
			}

			decryptedData, excludedBids, errors := decryptAllBids(encBids, km)
			assert.Equal(t, 0, len(errors))
			assert.Equal(t, 0, len(excludedBids))

			finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
			assert.Equal(t, 1, len(finalBids))
			assert.Equal(t, tt.expectedPrice, finalBids[0].Price)
		})
	}
}

func TestDecryptBids_HashAlgorithmMismatch(t *testing.T) {
	km, _ := NewKeyManager()

	tests := []struct {
		name            string
		encryptHashAlg  HashAlgorithm
		declaredHashAlg string
	}{
		{
			name:            "encrypted with SHA-1, declared SHA-256",
			encryptHashAlg:  HashAlgorithmSHA1,
			declaredHashAlg: "SHA-256",
		},
		{
			name:            "encrypted with SHA-256, declared SHA-1",
			encryptHashAlg:  HashAlgorithmSHA256,
			declaredHashAlg: "SHA-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{
				"price": 5.00,
			}
			plaintextBytes, _ := json.Marshal(payload)
			result, _ := EncryptHybridWithHash(plaintextBytes, km.PublicKey, tt.encryptHashAlg)

			encBids := []enclaveapi.EncryptedCoreBid{
				{
					CoreBid: core.CoreBid{
						ID:     "bid1",
						Bidder: "bidder1",
					},
					EncryptedPrice: &enclaveapi.EncryptedBidPrice{
						AESKeyEncrypted:  result.EncryptedAESKey,
						EncryptedPayload: result.EncryptedPayload,
						Nonce:            result.Nonce,
						HashAlgorithm:    tt.declaredHashAlg,
					},
				},
			}

			decryptedData, excludedBids, errors := decryptAllBids(encBids, km)
			assert.Equal(t, 1, len(errors))
			assert.Equal(t, 1, len(excludedBids))
			assert.Equal(t, 0, len(decryptedData))
		})
	}
}

func TestDecryptBids_MixedHashAlgorithms(t *testing.T) {
	km, _ := NewKeyManager()

	payload1 := map[string]any{"price": 3.50}
	plaintext1, _ := json.Marshal(payload1)
	result1, _ := EncryptHybridWithHash(plaintext1, km.PublicKey, HashAlgorithmSHA256)

	payload2 := map[string]any{"price": 5.25}
	plaintext2, _ := json.Marshal(payload2)
	result2, _ := EncryptHybridWithHash(plaintext2, km.PublicKey, HashAlgorithmSHA1)

	payload3 := map[string]any{"price": 4.75}
	plaintext3, _ := json.Marshal(payload3)
	result3, _ := EncryptHybridWithHash(plaintext3, km.PublicKey, HashAlgorithmSHA256)

	encBids := []enclaveapi.EncryptedCoreBid{
		{
			CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1"},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  result1.EncryptedAESKey,
				EncryptedPayload: result1.EncryptedPayload,
				Nonce:            result1.Nonce,
				HashAlgorithm:    "SHA-256",
			},
		},
		{
			CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder2"},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  result2.EncryptedAESKey,
				EncryptedPayload: result2.EncryptedPayload,
				Nonce:            result2.Nonce,
				HashAlgorithm:    "SHA-1",
			},
		},
		{
			CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder3"},
			EncryptedPrice: &enclaveapi.EncryptedBidPrice{
				AESKeyEncrypted:  result3.EncryptedAESKey,
				EncryptedPayload: result3.EncryptedPayload,
				Nonce:            result3.Nonce,
				// No HashAlgorithm - defaults to SHA-256
			},
		},
	}

	decryptedData, excludedBids, errors := decryptAllBids(encBids, km)
	assert.Equal(t, 0, len(errors))
	assert.Equal(t, 0, len(excludedBids))

	finalBids, _ := filterBidsByConsumedTokens(decryptedData, make(map[string]bool))
	assert.Equal(t, 3, len(finalBids))
	assert.Equal(t, 3.50, finalBids[0].Price)
	assert.Equal(t, 5.25, finalBids[1].Price)
	assert.Equal(t, 4.75, finalBids[2].Price)
}
