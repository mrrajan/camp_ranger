# Camp Ranger

SBOM correlation tool that fetches and correlates Software Bill of Materials (SBOMs) from TPA API or local directory.

## Overview

Camp Ranger analyzes and correlates SBOMs to build a dependency graph, ranking components based on their relationships. It supports both online mode (fetching from TPA API) and offline mode (reading from local directory).

## How to Run

### Build

```bash
cargo build --release
```

### Run - Online Mode (Fetch from TPA API)

```bash
cargo run -- \
  --tpa_api_url <TPA_API_URL> \
  --issuer_url <OIDC_ISSUER_URL> \
  --tpa_api_client_id <CLIENT_ID> \
  --tpa_api_client_secret <CLIENT_SECRET>
```

Add `--accept_invalid_certs` flag to accept self-signed SSL certificates (insecure).

### Run - Offline Mode (Read from Directory)

```bash
cargo run -- --sbom_dir <PATH_TO_SBOM_DIR>
```

## Output

- SBOMs are saved to `sboms/` directory (online mode)
- Logs are written to `camp_ranger_sbom.log`
- Console output shows correlation results with component rankings
