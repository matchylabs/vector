# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Vector is a high-performance, end-to-end observability data pipeline built in Rust. It collects, transforms, and routes logs, metrics, and traces to any vendor. The project emphasizes reliability (built in Rust), performance (up to 10x faster than alternatives), and vendor neutrality.

## Development Commands

### Building

```bash
# Development build (faster iteration)
cargo build
make build-dev

# Release build (optimized)
cargo build --release
make build

# Build with specific features only (much faster for development)
cargo build --no-default-features --features "sinks-console"
```

### Testing

Vector uses `cargo-nextest` for unit tests. You must have it installed: `cargo install cargo-nextest`

```bash
# Run all unit tests
cargo nextest run
make test

# Run specific component tests (much faster)
cargo nextest run --no-default-features --features "sinks-console" sinks::console
make test SCOPE="sinks::console"

# Run doc tests (nextest doesn't support these)
cargo test --doc
make test-docs

# Run integration tests (requires Docker/Podman)
cargo vdev int test aws
make test-integration-aws

# Run behavioral tests
make test-behavior

# Run a single integration test
cargo vdev int test kafka
```

### Code Quality

```bash
# Format code (always run before committing)
cargo fmt
make fmt

# Check code (Clippy)
cargo clippy
cargo vdev check rust
make check-clippy

# Auto-fix Clippy issues
cargo vdev check rust --fix

# Run all checks (slow, comprehensive)
make check-all
```

### Using `cargo vdev`

Vector has a custom development tool called `vdev` that simplifies common tasks:

```bash
# Install vdev
cargo install -f --path vdev

# Run unit tests
cargo vdev test

# Run integration tests
cargo vdev int show          # List available integration tests
cargo vdev int test <name>   # Run specific integration test

# Check code
cargo vdev check rust        # Clippy
cargo vdev check fmt         # Format checking
cargo vdev check licenses    # License compliance
cargo vdev check component-docs  # Component documentation

# Build tasks
cargo vdev build component-docs  # Generate component docs
cargo vdev build licenses        # Update LICENSE-3rdparty.csv
```

## Architecture

### Component Model

Vector has three core component types:

1. **Sources** - Collect data from external systems (files, sockets, cloud services, etc.)
2. **Transforms** - Process and modify events (filter, parse, aggregate, etc.)
3. **Sinks** - Send data to external systems (databases, cloud services, etc.)

Components are connected in a directed acyclic graph (DAG) defined in the user's configuration.

### Key Directories

- **`src/sources/`** - All source implementations
- **`src/transforms/`** - All transform implementations
- **`src/sinks/`** - All sink implementations
- **`src/config/`** - Configuration parsing and validation
- **`src/topology/`** - Component graph construction and execution
- **`src/internal_events/`** - Instrumentation and telemetry events
- **`lib/`** - Reusable libraries that don't depend on Vector core
  - `vector-lib/` - Core shared library
  - `vector-core/` - Core data structures and traits
  - `vector-config/` - Configuration schema and macros
  - `codecs/` - Encoding/decoding implementations

### Runtime Architecture

- Each component runs as a Tokio task
- Components are connected via channels
- Sources have a "pump" task that forwards output to downstream components
- Transforms can be synchronous (function-style) or asynchronous (task-style)
- Sinks have buffers (memory or disk) to handle backpressure

### Feature Flags

All components are behind feature flags. When developing:

```bash
# Work on a specific component only (faster builds)
cargo build --no-default-features --features "sinks-console"

# Default features for different platforms
default                 # Linux GNU (includes most features)
default-msvc           # Windows MSVC
default-musl           # Linux MUSL
default-cmake          # Linux with cmake dependencies
```

### Adding New Components

When adding a new source, sink, or transform:

1. Add feature flag in `Cargo.toml` (e.g., `sources-mycomponent`)
2. Add component to appropriate feature group
3. Implement the component trait (`SourceConfig`, `TransformConfig`, or `SinkConfig`)
4. Add instrumentation using `internal_events`
5. Add integration tests if connecting to external services
6. Update `.github/workflows/` integration test matrices
7. Add documentation (component docs are auto-generated from code)

## Code Style Guidelines

### Logging

Always use Tracing's key/value style:

```rust
// Good
warn!(message = "Failed to merge value.", %error);

// Bad
warn!("Failed to merge value: {}", err);
```

- Capitalize events and end with period
- Use `%error` (Display) not `?error` (Debug)
- Never abbreviate to `e` or `err`, always spell out `error`

### Panics

Code should **not panic** except in rare cases where assumptions about internal state are violated (clear bugs). All potential panics must be documented in function docs.

### Dependencies

- Carefully vet all new dependencies
- Make component-specific dependencies optional (tied to feature flags)
- Run `cargo vdev build licenses` and commit after adding/updating deps

## Testing Best Practices

### Fast Iteration for Component Development

```bash
# Install cargo-watch
cargo install cargo-watch

# Auto-run tests on file changes (specific component)
cargo watch -s clear -s \
  'cargo nextest run --lib --no-default-features --features=transforms-remap transforms::remap'
```

### Integration Tests

- Must run in Docker/Podman containers
- Use unique ports configured via environment variables
- Add to `make test-integration-<name>` in Makefile
- Requires `AUTOSPAWN=true` (default) or manual service setup

### Disabling Internal Log Rate Limiting

During development:

```bash
# Globally
vector --config vector.yaml -r 1
VECTOR_INTERNAL_LOG_RATE_LIMIT=1 vector --config vector.yaml

# Per statement
warn!(message = "Error occurred.", %error, internal_log_rate_limit = false);
```

## Docker/Podman Development Environment

For consistent builds and CI parity:

```bash
# Enter development container
make environment

# Run commands inside container
make environment CONTAINER_TOOL="podman"

# Run checks from outside container
make check ENVIRONMENT=true
make test ENVIRONMENT=true
make test-integration ENVIRONMENT=true
```

## Cross-Compilation

```bash
# Build for different architectures
make cross-build-x86_64-unknown-linux-gnu
make cross-build-aarch64-unknown-linux-gnu
make cross-build-x86_64-unknown-linux-musl

# Or using cross directly
cargo install cross
cross build --target aarch64-unknown-linux-gnu --release
```

## Common Development Workflows

### Working on a Single Component

```bash
# Fast iteration cycle
cargo watch -s clear -s \
  'cargo nextest run --lib --no-default-features \
   --features=sinks-http sinks::http'

# Build and test manually
cargo build --no-default-features --features "sinks-http"
cargo nextest run --no-default-features --features "sinks-http" sinks::http
```

### Running Integration Tests Locally

```bash
# List available integration tests
cargo vdev int show

# Run specific integration test
cargo vdev int test kafka

# Use AUTOSPAWN=false if you have service running already
AUTOSPAWN=false make test-integration-kafka
```

### Making Changes to Configuration Schema

```bash
# After modifying config structs with derive macros
make generate-component-docs

# Verify the docs were updated correctly
make check-component-docs
```

### Benchmarking

```bash
# Run all benchmarks
make bench

# Run specific benchmark suite
make bench-remap
make bench-transform
cargo bench --no-default-features --features "remap-benches" remap
```

## Profiling

Use `perf` on Linux for profiling:

```bash
# Build with debug symbols
# (Add debug = true to [profile.release] in Cargo.toml)

# Run Vector with your config
cargo run --release -- --config test.yaml

# In another terminal, profile it
perf record -F99 --call-graph dwarf -p <VECTOR_PID>

# Generate flamegraph
cargo install inferno
perf script | inferno-collapse-perf > stacks.folded
cat stacks.folded | inferno-flamegraph > flamegraph.svg
```

## Kubernetes Development

When working on Kubernetes integration:

```bash
# Use Tilt for automatic rebuilds and deploys
tilt up

# Run E2E tests
CONTAINER_IMAGE_REPO=<your-dockerhub>/vector-test make test-e2e-kubernetes

# Quick iteration (development builds)
QUICK_BUILD=true USE_MINIKUBE_CACHE=true make test-e2e-kubernetes
```

## Important Notes

- **Minimum Rust Version**: Check `rust-version` in `Cargo.toml` (currently 1.88)
- **CI**: All PRs run checks, unit tests, integration tests, and behavioral tests
- **Healthchecks**: Sinks can implement healthchecks. Prefer false positives over false negatives
- **License Compliance**: Update `LICENSE-3rdparty.csv` with `make build-licenses` after dependency changes
- **Conventional Commits**: PR titles must follow conventional commit format (enforced by CI)

## Resources

- **User Documentation**: https://vector.dev/docs
- **Rust API Docs**: https://rust-doc.vector.dev
- **Contributing Guide**: See `CONTRIBUTING.md` for detailed contribution workflow
- **Development Guide**: See `docs/DEVELOPING.md` for in-depth development documentation
- **Architecture**: See `docs/ARCHITECTURE.md` for internal architecture details
- **Community**: Discord at https://chat.vector.dev
