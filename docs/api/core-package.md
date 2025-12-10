# Core Package API Reference

The `core` package provides the foundational auction logic for bid processing, ranking, adjustment, and floor enforcement.

## Overview

Import path: `github.com/cloudx-io/openauction/core`

The core package is designed to be used both in TEE (Trusted Execution Environment) enclaves and in standard server environments. It provides a unified auction implementation with deterministic behavior.

## Types

### CoreBid

Represents a single bid in the auction system.

```go
type CoreBid struct {
    ID       string  `json:"id"`        // Unique bid identifier
    Bidder   string  `json:"bidder"`    // Bidder name/identifier
    Price    float64 `json:"price"`     // Bid price (must be positive)
    Currency string  `json:"currency"`  // Currency code (e.g., "USD")
    DealID   string  `json:"deal_id,omitempty"`   // Optional deal identifier
    BidType  string  `json:"bid_type,omitempty"`  // Optional bid type
}
```

### CoreRankingResult

Contains the ranked bidders and their highest bids.

```go
type CoreRankingResult struct {
    Ranks         map[string]int      `json:"ranks"`          // Bidder to rank mapping (1-indexed)
    HighestBids   map[string]*CoreBid `json:"highest_bids"`   // Bidder to highest bid
    SortedBidders []string            `json:"sorted_bidders"` // Bidders in rank order
}
```

### AuctionResult

Contains the complete results of running an auction.

```go
type AuctionResult struct {
    // Winner is the highest-ranked bid (nil if no valid bids)
    Winner *CoreBid

    // RunnerUp is the second-highest-ranked bid (nil if less than 2 valid bids)
    RunnerUp *CoreBid

    // EligibleBids contains all bids that passed floor enforcement
    EligibleBids []CoreBid

    // PriceRejectedBidIDs contains IDs of bids rejected due to invalid prices
    PriceRejectedBidIDs []string

    // FloorRejectedBidIDs contains IDs of bids that failed floor enforcement
    FloorRejectedBidIDs []string
}
```

### ExcludedBid

Represents a bid that was excluded from the auction.

```go
type ExcludedBid struct {
    BidID  string `json:"bid_id"`
    Reason string `json:"reason"` // e.g., "floor_rejection", "decryption_failed"
}
```

### RandSource

Interface for random number generation used in tie-breaking.

```go
type RandSource interface {
    // Intn returns a random integer in [0, n). Panics if n <= 0.
    Intn(n int) int
}
```

**Note**: This interface enables dependency injection for deterministic testing. Production code uses `crypto/rand` by default.

## Functions

### RunAuction

Executes the complete auction logic: price validation → adjustment → floor enforcement → ranking.

```go
func RunAuction(
    bids []CoreBid,
    adjustmentFactors map[string]float64,
    bidFloor float64,
) *AuctionResult
```

**Parameters:**
- `bids`: Input bids (should already be decrypted if from TEE)
- `adjustmentFactors`: Per-bidder adjustment multipliers (e.g., `{"bidder-a": 0.95}`)
- `bidFloor`: Minimum acceptable bid price

**Returns:**
- `*AuctionResult` containing winner, runner-up, eligible bids, and rejected bid IDs

**Processing Flow:**
1. Validate bid prices (reject non-positive prices)
2. Apply bid adjustment factors (multipliers per bidder)
3. Enforce floor price
4. Rank eligible bids by price with random tie-breaking
5. Extract winner and runner-up from ranking

**Example:**

```go
bids := []core.CoreBid{
    {ID: "1", Bidder: "bidder-a", Price: 2.5, Currency: "USD"},
    {ID: "2", Bidder: "bidder-b", Price: 3.0, Currency: "USD"},
    {ID: "3", Bidder: "bidder-a", Price: 2.8, Currency: "USD"}, // Lower than first bid
}

adjustments := map[string]float64{
    "bidder-a": 0.95, // 5% penalty
}

result := core.RunAuction(bids, adjustments, 2.0)

fmt.Printf("Winner: %s at $%.2f\n", result.Winner.Bidder, result.Winner.Price)
fmt.Printf("Runner-up: %s at $%.2f\n", result.RunnerUp.Bidder, result.RunnerUp.Price)
fmt.Printf("Rejected (floor): %v\n", result.FloorRejectedBidIDs)
```

### RankCoreBids

Ranks bids by price with cryptographically secure random tie-breaking.

```go
func RankCoreBids(bids []CoreBid, randSource RandSource) *CoreRankingResult
```

**Parameters:**
- `bids`: Bids to rank
- `randSource`: Random source for tie-breaking (pass `nil` to use crypto/rand)

**Returns:**
- `*CoreRankingResult` with ranked bidders

**Behavior:**
- Finds the highest bid per bidder
- Sorts bidders by price (descending)
- **Tie-Breaking**: When multiple bids have the same price, they are randomly shuffled using cryptographically secure randomness via Fisher-Yates shuffle
- For testing, inject a custom `RandSource` to make tie-breaking deterministic

**Example:**

```go
bids := []core.CoreBid{
    {ID: "1", Bidder: "bidder-a", Price: 2.5, Currency: "USD"},
    {ID: "2", Bidder: "bidder-b", Price: 3.0, Currency: "USD"},
}

// Use default crypto/rand for production
result := core.RankCoreBids(bids, nil)

// Access results
for i, bidder := range result.SortedBidders {
    bid := result.HighestBids[bidder]
    rank := result.Ranks[bidder]
    fmt.Printf("#%d: %s - $%.2f\n", rank, bidder, bid.Price)
}
```

### ApplyBidAdjustmentFactors

Applies per-bidder price adjustment multipliers with optional currency conversion.

```go
func ApplyBidAdjustmentFactors(
    bids []CoreBid,
    adjustmentFactors map[string]float64,
    conversionRate float64,
) []CoreBid
```

**Parameters:**
- `bids`: Input bids
- `adjustmentFactors`: Per-bidder multipliers (case-insensitive bidder names)
- `conversionRate`: Currency conversion multiplier (use 1.0 for no conversion)

**Returns:**
- New slice with adjusted bid prices

**Formula:**
```
adjusted_price = original_price * adjustment_factor * conversion_rate
```

**Note**: Uses `decimal` package for precise monetary calculations to avoid floating-point errors.

**Example:**

```go
bids := []core.CoreBid{
    {ID: "1", Bidder: "bidder-a", Price: 10.0, Currency: "USD"},
    {ID: "2", Bidder: "bidder-b", Price: 10.0, Currency: "USD"},
}

// Apply 10% penalty to bidder-a
adjustments := map[string]float64{
    "bidder-a": 0.90,
}

adjusted := core.ApplyBidAdjustmentFactors(bids, adjustments, 1.0)
// bidder-a: 9.0, bidder-b: 10.0
```

### ApplySingleBidAdjustmentFactor

Applies adjustment to a single bid price with fallback bidder support.

```go
func ApplySingleBidAdjustmentFactor(
    bidPrice float64,
    bidderName string,
    fallbackBidderName string,
    adjustmentFactors map[string]float64,
    conversionRate float64,
) float64
```

**Parameters:**
- `bidPrice`: Original bid price
- `bidderName`: Primary bidder name to look up
- `fallbackBidderName`: Fallback bidder name if primary not found
- `adjustmentFactors`: Per-bidder multipliers
- `conversionRate`: Currency conversion multiplier

**Returns:**
- Adjusted bid price

### EnforceBidFloor

Filters bids based on minimum floor price.

```go
func EnforceBidFloor(
    bids []CoreBid,
    floor float64,
) (eligible []CoreBid, rejectedBidIDs []string)
```

**Parameters:**
- `bids`: Input bids
- `floor`: Minimum acceptable bid price

**Returns:**
- `eligible`: Bids that meet or exceed the floor
- `rejectedBidIDs`: IDs of bids below the floor

**Example:**

```go
bids := []core.CoreBid{
    {ID: "1", Bidder: "bidder-a", Price: 2.5, Currency: "USD"},
    {ID: "2", Bidder: "bidder-b", Price: 1.5, Currency: "USD"},
}

eligible, rejected := core.EnforceBidFloor(bids, 2.0)
// eligible: [bid 1]
// rejected: ["2"]
```

### BidMeetsFloor

Checks if a single bid price meets or exceeds the floor price.

```go
func BidMeetsFloor(bidPrice, floorPrice float64) bool
```

**Parameters:**
- `bidPrice`: Bid price to check
- `floorPrice`: Minimum acceptable price

**Returns:**
- `true` if bid meets or exceeds floor, `false` otherwise

**Note**: Uses decimal arithmetic with 4 decimal places precision (0.0001) to avoid floating-point comparison errors.

## Constants

### monetaryPrecision

```go
const monetaryPrecision int32 = 4 // 4 decimal places for CPM values
```

Defines the precision used for monetary comparisons (0.0001 precision).

## Best Practices

1. **Price Validation**: Always use `RunAuction` which includes price validation, or validate prices before processing
2. **Tie-Breaking**: Use default `nil` RandSource for production to ensure cryptographic randomness
3. **Decimal Precision**: The package uses `shopspring/decimal` for monetary calculations to avoid floating-point errors
4. **Bidder Case Sensitivity**: Adjustment factors use case-insensitive bidder name matching
5. **Immutability**: Functions return new slices/structs rather than modifying inputs

## Thread Safety

All functions in the core package are **thread-safe** and **stateless**. They can be called concurrently from multiple goroutines without synchronization.

The only exception is the `RandSource` interface - if you provide a custom implementation, ensure it's thread-safe.
