# CloudX's Open Auction

Core auction logic and TEE (Trusted Execution Environment) enclave implementation for CloudX auctions.

## Overview

This repository contains the core auction functionality that has been extracted from the main CloudX platform for independent versioning and reusability. It includes:

- **`core/`**: Core auction logic including bid ranking, adjustments, and floor enforcement
- **`enclaveapi/`**: API types for TEE enclave communication
- **`enclave/`**: AWS Nitro Enclave implementation for secure auction processing

## Usage

### Importing in Go

```go
import (
    "github.com/cloudx-io/openauction/core"
    "github.com/cloudx-io/openauction/enclaveapi"
    "github.com/cloudx-io/openauction/enclave"
)
```

### Example: Ranking Bids

```go
bids := []core.CoreBid{
    {ID: "1", Bidder: "bidder-a", Price: 2.5, Currency: "USD"},
    {ID: "2", Bidder: "bidder-b", Price: 3.0, Currency: "USD"},
}

// RankCoreBids accepts a RandSource for tie-breaking
// Pass nil to use crypto/rand (default, production behavior)
result := core.RankCoreBids(bids, nil)
fmt.Printf("Winner ID: %s, Price: %.2f\n", result.HighestBids[result.SortedBidders[0]].ID, result.HighestBids[result.SortedBidders[0]].Price)
```

**Tie-Breaking**: When multiple bids have the same price, they are randomly shuffled using cryptographically secure randomness (`crypto/rand`). This ensures fairness in tie scenarios. For testing purposes, you can inject a custom `RandSource` implementation into `RankCoreBids` to make tie-breaking deterministic.

## Development

### Running Tests

```bash
go test ./...
```

### Building the Enclave

The enclave binary can be built using the Dockerfile:

```bash
docker build -f enclave/Dockerfile -t auction-enclave .
```
