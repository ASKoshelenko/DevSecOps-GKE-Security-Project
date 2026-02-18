# Trivy Vulnerability Database Compression Research

## Overview

This document details the compression mechanisms used by [Trivy](https://github.com/aquasecurity/trivy) for its vulnerability database (trivy-db) and Java vulnerability database (trivy-java-db). Understanding these mechanisms is essential for network planning, air-gapped deployments, and performance tuning in our GKE-based DevSecOps pipeline.

## Compression Algorithms

Trivy uses **two primary compression algorithms** depending on the component:

### 1. Gzip Compression (Primary - OCI Layer Compression)

The vulnerability database is distributed as an **OCI (Open Container Initiative) artifact** via container registries (default: `ghcr.io/aquasecurity/trivy-db`). The OCI layers use **gzip compression** as the standard layer media type.

**Source code references:**

- `pkg/db/db.go` - Database initialization and download orchestration
- `pkg/oci/artifact.go` - OCI artifact download with layer decompression
- `pkg/fanal/artifact/image/image.go` - Image layer handling with gzip decompression

The OCI artifact layers use the media type `application/vnd.oci.image.layer.v1.tar+gzip`, which is the standard OCI compressed layer format. When Trivy downloads the DB, it pulls the OCI manifest, identifies the layers, and decompresses them using Go's standard `compress/gzip` package.

**Relevant code pattern (from `pkg/oci/artifact.go`):**

```go
// The OCI artifact is pulled using go-containerregistry (GGCR) library
// which handles gzip decompression of layers transparently.
// The layer media type application/vnd.oci.image.layer.v1.tar+gzip
// signals gzip compression.

img, err := remote.Image(ref, opts...)
layers, err := img.Layers()
for _, layer := range layers {
    rc, err := layer.Compressed()  // Returns gzip-compressed stream
    // or
    rc, err := layer.Uncompressed()  // Returns decompressed tar stream
}
```

### 2. Zstd Compression (Database Internal Compression)

Starting with newer versions, Trivy's underlying key-value store uses **Zstandard (zstd)** compression for the database files themselves. The vulnerability database is built on [BoltDB](https://github.com/etcd-io/bbolt) (via the trivy-db project), and the data within is serialized and compressed.

**Source code references:**

- `pkg/db/db.go` - Uses bbolt for database operations
- In the `aquasecurity/trivy-db` repository:
  - `pkg/db/db.go` - Database build and compression logic
  - `pkg/vulnsrc/` - Vulnerability source processors that compress advisory data

**Relevant code pattern:**

```go
// From trivy-db: pkg/db/db.go
// Advisory data is compressed before storage in BoltDB buckets
// to reduce the on-disk (and in-transit) database size.

import "github.com/klauspost/compress/zstd"

func compress(data []byte) ([]byte, error) {
    encoder, err := zstd.NewWriter(nil,
        zstd.WithEncoderLevel(zstd.SpeedDefault),
    )
    if err != nil {
        return nil, err
    }
    return encoder.EncodeAll(data, make([]byte, 0, len(data))), nil
}

func decompress(data []byte) ([]byte, error) {
    decoder, err := zstd.NewReader(nil)
    if err != nil {
        return nil, err
    }
    defer decoder.Close()
    return decoder.DecodeAll(data, nil)
}
```

The `github.com/klauspost/compress/zstd` package is the Go implementation of Facebook's Zstandard algorithm, providing:
- Compression ratios comparable to gzip at higher speed levels
- Significantly faster decompression than gzip
- Dictionary support for improved ratios on small data blocks

## How Compression Works in the Scanning Pipeline

The full flow of compression in a Trivy scan involves multiple stages:

```
                    +---------------------------+
                    | ghcr.io/aquasecurity/     |
                    | trivy-db (OCI Registry)   |
                    +---------------------------+
                              |
                    [1] OCI Pull (gzip layers)
                              |
                              v
                    +---------------------------+
                    | Layer Decompression       |
                    | (gzip -> tar -> extract)  |
                    | pkg/oci/artifact.go       |
                    +---------------------------+
                              |
                    [2] Extract DB files
                              |
                              v
                    +---------------------------+
                    | BoltDB Database           |
                    | (db.gz / trivy.db)        |
                    | Stored in cache dir       |
                    +---------------------------+
                              |
                    [3] Query advisories
                              |
                              v
                    +---------------------------+
                    | Decompress Advisory Data  |
                    | (zstd decompression)      |
                    | pkg/db/db.go              |
                    +---------------------------+
                              |
                    [4] Match against image
                              |
                              v
                    +---------------------------+
                    | Vulnerability Report      |
                    | (JSON/Table output)       |
                    +---------------------------+
```

### Stage 1: OCI Artifact Download

Trivy uses the [go-containerregistry (GGCR)](https://github.com/google/go-containerregistry) library to pull the vulnerability database as an OCI artifact. The layers are stored in the registry with **gzip compression** (media type: `application/vnd.oci.image.layer.v1.tar+gzip`).

**Key files:**
- `pkg/oci/artifact.go` - Orchestrates OCI download
- Uses `github.com/google/go-containerregistry/pkg/v1/remote` for registry interaction

### Stage 2: Layer Extraction

After pulling, GGCR transparently decompresses the gzip layers and extracts the tar contents to Trivy's cache directory (default: `~/.cache/trivy/db/`). The decompressed database file is a BoltDB file (`trivy.db`).

### Stage 3: Advisory Lookup

When scanning an image, Trivy queries the BoltDB database for matching advisories. The advisory data stored in BoltDB buckets is **zstd-compressed** to reduce the database file size. Each advisory record is individually compressed.

**Key files:**
- `pkg/db/db.go` - Database query interface
- `pkg/vulnerability/vulnerability.go` - Advisory matching logic

### Stage 4: Report Generation

The decompressed advisory data is matched against the packages found in the scanned container image. Results are output as structured reports (JSON, table, SARIF, etc.) without additional compression.

## Database Size and Compression Ratios

Approximate sizes observed (these vary with each DB update):

| Stage | Format | Approximate Size |
|-------|--------|-----------------|
| OCI artifact (compressed) | gzip tar layers | ~35-45 MB |
| Extracted DB (on disk) | BoltDB file | ~150-200 MB |
| Individual advisory (compressed) | zstd | ~60-70% compression ratio |
| Java DB OCI artifact | gzip tar layers | ~50-70 MB |

## Implications for Our GKE Pipeline

### Network Bandwidth

- Each Trivy scan job (in Standalone mode) downloads ~40 MB for the vulnerability DB
- With multiple concurrent scans, this can generate significant egress traffic
- **Recommendation:** Use `ClientServer` mode or a registry mirror to reduce repeated downloads

### Air-Gapped Environments

- Mirror `ghcr.io/aquasecurity/trivy-db` to a private Artifact Registry
- The gzip-compressed OCI format is preserved during mirroring
- Use `trivy.dbRepository` Helm value to point to the private mirror

### Cache Optimization

- The extracted BoltDB file is ~200 MB and stored in the scan job's ephemeral storage
- Ensure scan job pods have sufficient ephemeral storage (`1Gi` recommended)
- In `ClientServer` mode, the DB is loaded once and shared via gRPC

### Scan Job Resource Requirements

- Decompression (both gzip and zstd) is CPU-intensive during DB download
- Advisory decompression (zstd) happens during scanning and requires memory
- The values.yaml resource limits (`500m` CPU, `1Gi` memory) account for this

## Key Dependencies

The compression implementations rely on these Go packages:

| Package | Purpose | Used In |
|---------|---------|---------|
| `compress/gzip` (stdlib) | OCI layer decompression | GGCR library |
| `github.com/klauspost/compress/zstd` | Advisory data compression/decompression | trivy-db, trivy |
| `github.com/google/go-containerregistry` | OCI artifact handling | pkg/oci/ |
| `go.etcd.io/bbolt` | Key-value database storage | pkg/db/ |

## Source Code Repository References

- **Trivy main repository:** https://github.com/aquasecurity/trivy
  - `pkg/db/` - Database management and querying
  - `pkg/oci/` - OCI artifact downloading
  - `pkg/fanal/` - File analysis and layer handling
  - `go.sum` - Lists `klauspost/compress` as a dependency
- **Trivy DB builder:** https://github.com/aquasecurity/trivy-db
  - `pkg/db/` - Database building with compression
  - `pkg/vulnsrc/` - Vulnerability source ingestion and compression
- **Trivy Operator:** https://github.com/aquasecurity/trivy-operator
  - Orchestrates scan jobs that use the above compression pipeline
