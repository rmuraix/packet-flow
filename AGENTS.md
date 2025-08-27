# Repository Guidelines

## Project Structure & Modules
- `src/main.rs`: CLI entry (clap). Initializes interface, receives frames via `pnet`, delegates to handlers.
- `src/handler.rs`: Dispatch by EtherType to IPv4/IPv6/ARP and transport protocols.
- `src/handler/{packets.rs,direction.rs}`: Parsers and pretty printers; `direction.rs` includes unit tests.
- `static/`: Assets (e.g., screenshot).
- `.github/workflows/build.yml`: CI for build/test/release.

## Build, Test, and Run
- Build: `cargo build` — debug binary at `target/debug/packet-flow`.
- Release build: `cargo build --release` — optimized binary at `target/release/packet-flow`.
- Tests: `cargo test` — runs unit tests (e.g., in `direction.rs`).
- Run locally: `sudo ./target/debug/packet-flow -i <iface>`
  - Note: `sudo` may be needed for packet capture permissions.
## Coding Style & Naming
- Rust 2021 edition; prefer idiomatic Rust.
- Format: `cargo fmt --all` before pushing.
- Lint: `cargo clippy -- -D warnings` for new/changed code.
- Naming: modules `snake_case`, types `UpperCamelCase`, functions/vars `snake_case`.
- Keep functions focused; route parsing/printing via handlers as in current layout.

## Testing Guidelines
- Place fast unit tests alongside modules with `#[cfg(test)]`.
- Name tests descriptively (e.g., `test_is_destination`).
- Add tests for protocol parsing branches you touch; run `cargo test` locally and in CI.

## Commit & Pull Requests
- Commits: imperative mood and scoped, e.g., `handler: print DNS as UDP/DNS`.
- PRs must:
  - Describe changes, rationale, and affected protocols/flags.
  - Link related issues.
  - Include sample run output if changing logs/formatting.
  - Pass CI (build + tests on Ubuntu/macOS) with formatted, linted code.

## Security & Platform Notes
- Packet capture may require elevated privileges; prefer Linux capabilities over full sudo for binaries.
- Windows builds require pnet prerequisites (see README “Requirement”).
