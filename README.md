# CloudX's Open Auction

Core auction logic and TEE (Trusted Execution Environment) enclave implementation for CloudX auctions.

https://www.cloudx.ai/

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

## Auction rules

`core.RunAuction` applies the same rules on the host and inside the enclave, in this order. The enclave also rejects a malformed deal list before the auction runs (see Deals).

**Price.** A bid must be priced above zero. The one exception is a bid priced at exactly zero that names a deal the round lists: that bid is valid, and a price of `-0` counts as zero. Every other bid, including every negative bid, is rejected for an invalid price.

**Adjustment.** Each valid bid's price is multiplied by its bidder's adjustment factor, when one is set. A zero price stays zero.

**Floor.** A bid that names a listed deal must meet that deal's floor. Every other bid must meet the round floor. Prices and floors are compared at four decimal places.

**Ranking.** Each bidder's highest eligible bid is ranked by price, highest first, and bids at the same price are ordered at random. Deal bids and open-auction bids rank together: naming a deal does not give a bid priority. The auction is first price, so the top bid wins at its own price and the second is the runner-up.

**Deals.** The host lists the deals on the round's impression as `core.Deal` values, which carry the ID and floor of each entry in OpenRTB `imp.pmp.deals`. A bid names a deal with its deal ID. A deal ID that the round does not list has no effect: that bid competes as an open-auction bid, though if it is the winner or runner-up the attestation still shows its deal ID. The auction does not read `Deal.at`, `Deal.wseat` or `Pmp.private_auction`: before the bids reach the auction, the host decides which seats may bid on a deal and whether bids outside the deals are accepted. The enclave rejects a request whose deal list has an empty ID, an ID containing `|`, a repeated ID, or a negative or non-finite floor. `RunAuction` itself assumes a valid list, so a host that runs it in process should call `core.ValidateDeals` first; a non-finite deal floor would panic.

**Attestation.** The attestation's signed user data records the round floor as `bid_floor` and the round's deal list, verbatim, as `deals`, where each entry has an `id` and a `bid_floor`. The order of `deals` carries no meaning. Every bid that reached the auction, including bids the rules then rejected, is attested as one lowercase-hex SHA-256 digest in `bid_hashes`, computed with the nonce in `bid_hash_nonce`. The hashed price is the price the bidder submitted (the decrypted price for a sealed bid) before any adjustment, formatted with six decimal places, so zero is `0.000000`. An open bid, or a bid that names a deal the round does not list, hashes as `SHA256("<bid_id>|<price>|<nonce>")`. A bid that names a listed deal hashes as `SHA256("<bid_id>|<price>|deal:<deal_id>|<nonce>")`, which binds the deal the auction applied to that bid; `|` and `deal:` are literal. A bidder validates its bid by checking that every deal in its own bid request is attested with the same floor, that any attested deal its bid names was in that request, that its bid hash is present in the form its own deal ID selects, and, if it won, that the attested winner carries its deal ID. An attested deal the bidder was not sent is not an error, because an exchange may send each seat only the deals open to it. The deal list is visible to every party that receives the attestation, so listing a deal discloses its ID and floor to all of them, including seats that were not sent it.

## Development

### Running Tests

```bash
go test ./...
```

### Building the Enclave

The Dockerfile copies a prebuilt binary from `./bin/`, so build the binary first. These commands match the arm64 build in `.github/workflows/docker.yml`:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -ldflags '-extldflags "-static"' -tags netgo -o ./bin/tee-auction-enclave ./enclave
docker build --platform linux/arm64 -f enclave/Dockerfile -t auction-enclave .
```

For an amd64 image, use `GOARCH=amd64` and `--platform linux/amd64`.
