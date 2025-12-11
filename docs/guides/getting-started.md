# Getting Started with OpenAuction

This guide will help you get started using the OpenAuction library for your auction system.

## Installation

Add OpenAuction to your Go project:

```bash
go get github.com/cloudx-io/openauction
```

## Quick Start: Basic Auction

The simplest way to run an auction is using the `core` package:

```go
package main

import (
    "fmt"
    "github.com/cloudx-io/openauction/core"
)

func main() {
    // Create bids
    bids := []core.CoreBid{
        {
            ID:       "bid-1",
            Bidder:   "bidder-a",
            Price:    2.50,
            Currency: "USD",
        },
        {
            ID:       "bid-2",
            Bidder:   "bidder-b",
            Price:    3.00,
            Currency: "USD",
        },
        {
            ID:       "bid-3",
            Bidder:   "bidder-c",
            Price:    2.20,
            Currency: "USD",
        },
    }

    // Run auction with no adjustments and $2.00 floor
    result := core.RunAuction(bids, nil, 2.00)

    // Display results
    if result.Winner != nil {
        fmt.Printf("Winner: %s at $%.2f\n",
            result.Winner.Bidder, result.Winner.Price)
    }

    if result.RunnerUp != nil {
        fmt.Printf("Runner-up: %s at $%.2f\n",
            result.RunnerUp.Bidder, result.RunnerUp.Price)
    }

    fmt.Printf("Total eligible bids: %d\n", len(result.EligibleBids))
}
```

**Output:**
```
Winner: bidder-b at $3.00
Runner-up: bidder-a at $2.50
Total eligible bids: 3
```

## Bid Adjustments

Apply per-bidder price adjustments (penalties or bonuses):

```go
// Define adjustment factors (multipliers)
adjustments := map[string]float64{
    "bidder-a": 0.90, // 10% penalty
    "bidder-b": 1.05, // 5% bonus
}

result := core.RunAuction(bids, adjustments, 2.00)
```

**How it works:**
- Original price × adjustment factor = adjusted price
- Factor < 1.0 = penalty (reduces effective bid)
- Factor > 1.0 = bonus (increases effective bid)
- Factor = 1.0 or missing = no adjustment

## Floor Price Enforcement

Reject bids below a minimum price:

```go
// Set floor at $2.50
result := core.RunAuction(bids, nil, 2.50)

// Check rejected bids
if len(result.FloorRejectedBidIDs) > 0 {
    fmt.Printf("Rejected (floor): %v\n", result.FloorRejectedBidIDs)
}
```

Bids with prices below the floor are excluded from ranking and returned in `FloorRejectedBidIDs`.

## Handling Multiple Bids Per Bidder

The auction automatically selects the highest bid from each bidder:

```go
bids := []core.CoreBid{
    {ID: "bid-1", Bidder: "bidder-a", Price: 2.50, Currency: "USD"},
    {ID: "bid-2", Bidder: "bidder-a", Price: 3.00, Currency: "USD"}, // Higher
    {ID: "bid-3", Bidder: "bidder-b", Price: 2.80, Currency: "USD"},
}

result := core.RunAuction(bids, nil, 0)
// bidder-a will be represented by bid-2 (Price: 3.00)
```

## Tie-Breaking

When multiple bids have the same price, the system uses **cryptographically secure random tie-breaking**:

```go
bids := []core.CoreBid{
    {ID: "bid-1", Bidder: "bidder-a", Price: 3.00, Currency: "USD"},
    {ID: "bid-2", Bidder: "bidder-b", Price: 3.00, Currency: "USD"}, // Same price
}

// Winner selected randomly using crypto/rand
result := core.RunAuction(bids, nil, 0)
```

This ensures fairness when bids are equal. For deterministic testing, see the [Testing Guide](testing.md).

## Error Handling

The auction handles invalid bids automatically:

```go
bids := []core.CoreBid{
    {ID: "bid-1", Bidder: "bidder-a", Price: 2.50, Currency: "USD"},
    {ID: "bid-2", Bidder: "bidder-b", Price: 0.00, Currency: "USD"},    // Invalid
    {ID: "bid-3", Bidder: "bidder-c", Price: -1.00, Currency: "USD"},   // Invalid
}

result := core.RunAuction(bids, nil, 0)

// Check rejected bids
fmt.Printf("Invalid prices: %v\n", result.PriceRejectedBidIDs)
// Output: Invalid prices: [bid-2 bid-3]
```

**Validation Rules:**
- Bid price must be > 0.0
- Negative or zero prices are automatically rejected

## Complete Example

Here's a complete example with all features:

```go
package main

import (
    "fmt"
    "github.com/cloudx-io/openauction/core"
)

func main() {
    // Create bids
    bids := []core.CoreBid{
        {ID: "bid-1", Bidder: "bidder-a", Price: 2.50, Currency: "USD"},
        {ID: "bid-2", Bidder: "bidder-b", Price: 3.00, Currency: "USD"},
        {ID: "bid-3", Bidder: "bidder-c", Price: 2.20, Currency: "USD"},
        {ID: "bid-4", Bidder: "bidder-a", Price: 2.80, Currency: "USD"}, // Duplicate bidder
        {ID: "bid-5", Bidder: "bidder-d", Price: 0.00, Currency: "USD"},  // Invalid
    }

    // Apply adjustments
    adjustments := map[string]float64{
        "bidder-a": 0.95, // 5% penalty
        "bidder-c": 1.10, // 10% bonus
    }

    // Run auction with $2.00 floor
    result := core.RunAuction(bids, adjustments, 2.00)

    // Display results
    fmt.Println("=== Auction Results ===")

    if result.Winner != nil {
        fmt.Printf("🥇 Winner: %s (Bid: %s)\n",
            result.Winner.Bidder, result.Winner.ID)
        fmt.Printf("   Price: $%.2f\n", result.Winner.Price)
    }

    if result.RunnerUp != nil {
        fmt.Printf("🥈 Runner-up: %s (Bid: %s)\n",
            result.RunnerUp.Bidder, result.RunnerUp.ID)
        fmt.Printf("   Price: $%.2f\n", result.RunnerUp.Price)
    }

    fmt.Printf("\n📊 Stats:\n")
    fmt.Printf("   Eligible bids: %d\n", len(result.EligibleBids))
    fmt.Printf("   Floor rejected: %d\n", len(result.FloorRejectedBidIDs))
    fmt.Printf("   Invalid prices: %d\n", len(result.PriceRejectedBidIDs))

    if len(result.FloorRejectedBidIDs) > 0 {
        fmt.Printf("   Below floor: %v\n", result.FloorRejectedBidIDs)
    }

    if len(result.PriceRejectedBidIDs) > 0 {
        fmt.Printf("   Invalid: %v\n", result.PriceRejectedBidIDs)
    }
}
```

## Next Steps

- **[Basic Auction Usage](basic-auction.md)** - Detailed examples and patterns
- **[Bid Adjustments](bid-adjustments.md)** - Advanced adjustment strategies
- **[TEE Enclave Usage](tee-enclave.md)** - Using OpenAuction with AWS Nitro Enclaves
- **[E2EE Encryption](e2ee-encryption.md)** - End-to-end encrypted auctions
- **[Testing Guide](testing.md)** - Testing your auction implementation

## API References

- [Core Package](../api/core-package.md)
- [EnclaveAPI Package](../api/enclaveapi-package.md)
- [Validation Package](../api/validation-package.md)
