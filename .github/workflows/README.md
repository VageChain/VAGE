# GitHub Workflows for VAGE

This directory contains comprehensive GitHub Actions workflows for the VAGE blockchain project, matching industry best practices from top crypto projects like Solana, Ethereum, and Polkadot.

## Workflow Overview

### 1. **CI/CD Pipeline** (`rust.yml`)
Main continuous integration and deployment pipeline.

**Triggers:**
- Push to `main` or `develop`
- Pull requests to `main` or `develop`
- Manual trigger (`workflow_dispatch`)

**Jobs:**
- **Lint** - Format checks and clippy analysis
- **Build** - Multi-platform builds (Linux, macOS, Windows)
- **Test Suite** - Unit, integration, and doc tests
- **Feature Testing** - Cross-feature compilation tests
- **MIRI** - Undefined behavior detection
- **Unused Dependencies** - Clean dependency tree validation

**Key Features:**
- ✅ Parallel job execution for faster feedback
- ✅ Multi-platform testing (Ubuntu, macOS, Windows)
- ✅ Rust version matrix (stable + beta)
- ✅ Comprehensive caching for faster runs
- ✅ Undefined behavior detection with MIRI
- ✅ Feature powerset testing

---

### 2. **Security Audits** (`security.yml`)
Comprehensive security scanning and vulnerability detection.

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Daily schedule (2 AM UTC)
- Manual trigger

**Jobs:**
- **Cargo Audit** - CVE vulnerability scanning
- **Trivy** - Filesystem-level vulnerability scanning
- **SAST** - cargo-deny for dependency security
- **License Compliance** - Verify acceptable licenses
- **Secret Scanning** - TruffleHog secret detection
- **Code Quality** - Clippy with SARIF upload to GitHub Security tab
- **Dependencies Analysis** - Dependency tree audit

**Security Integrations:**
- 🔒 GitHub Security tab integration (automatic SARIF upload)
- 🔐 Secret scanning to prevent credential leaks
- 📋 License compliance for legal safety
- 🛡️ Multi-layer vulnerability detection

---

### 3. **Code Coverage** (`coverage.yml`)
Track and report code coverage metrics.

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Manual trigger

**Jobs:**
- **Tarpaulin Coverage** - Line/branch coverage analysis
- **LLVM Coverage** - Alternative coverage engine
- **Coverage Report** - Generate markdown reports
- **Coverage Gates** - Enforce minimum coverage thresholds

**Coverage Goals:**
- Line coverage: 75%+
- Branch coverage: 70%+
- Function coverage: 80%+

**Integration:**
- 📊 Automatic Codecov upload
- 💬 PR comments with coverage changes
- 📈 Coverage trend tracking

---

### 4. **Release & Deploy** (`release.yml`)
Automated release and deployment pipeline.

**Triggers:**
- Git tags matching `v*` pattern
- Manual workflow dispatch

**Jobs:**
- **Validate Release** - Verify version format and consistency
- **Build Binaries** - Multi-platform binary builds
  - Linux x86_64
  - macOS x86_64
  - macOS Apple Silicon (aarch64)
  - Windows x86_64
- **Generate Release Notes** - Automatic changelog generation
- **Create Release** - GitHub release with binary artifacts
- **Publish to Crates.io** - Automated crate publishing
- **Docker Image** - Build and push Docker images

**Release Artifacts:**
- 📦 Compiled binaries for all platforms
- 📝 Automated changelog
- 🐳 Docker containers
- ✅ SHA256 checksums

**Automatic Publishing:**
- crates.io (stable releases only)
- Docker Hub (if credentials configured)
- GitHub Releases (all versions)

---

### 5. **Documentation** (`docs.yml`)
Build and deploy documentation.

**Triggers:**
- Push to `main`
- Changes to docs or Rust code
- Manual trigger

**Jobs:**
- **Build Docs** - Generate Rust API documentation
- **Check Links** - Validate documentation links
- **Validate Markdown** - Lint and verify markdown docs
- **Build Guides** - Compile user guides
- **Deploy to GitHub Pages** - Auto-deploy on main branch

**Documentation Features:**
- 📚 Auto-generated API docs
- 🔗 Link validation
- 📖 Markdown linting with configuration
- 🌐 GitHub Pages deployment
- 🎯 Crate-specific documentation

**Published Documentation:**
- Rust API reference
- Setup guides
- Architecture documentation
- CLI command reference
- Configuration documentation

---

### 6. **Performance Benchmarks** (`benchmarks.yml`)
Track and report performance metrics.

**Triggers:**
- Push to `main`
- Pull requests
- Daily schedule (3 AM UTC)
- Manual trigger

**Jobs:**
- **Criterion Benchmarks** - Performance testing
- **Memory Profiling** - Memory usage analysis
- **Compile Times** - Track build time trends
- **Binary Size** - Monitor binary bloat
- **Regression Detection** - Compare PR vs main branch

**Benchmarking Features:**
- ⚡ Criterion.rs integration
- 💾 Memory profiling with flamegraph
- 📊 Binary size tracking
- 🔍 Regression detection for PRs
- ⏱️ Compilation time analysis

---

### 7. **Dependency Management** (`dependencies.yml`)
Track and manage project dependencies.

**Triggers:**
- Changes to Cargo.toml/Cargo.lock
- Weekly schedule
- Manual trigger

**Jobs:**
- **Outdated Dependencies** - Check for updates
- **Dependency Tree** - Analyze dependency graph
- **SBOM Generation** - Software Bill of Materials
- **Duplicate Detection** - Find duplicate versions
- **Vulnerability Scanning** - Security checks
- **License Compliance** - Verify all licenses
- **Minimal Versions** - MSRV compatibility
- **Update Recommendations** - Suggest upgrades

**Dependency Features:**
- 📦 SBOM in multiple formats
- 🔄 Duplicate dependency detection
- 🛡️ Security vulnerability tracking
- ⚖️ License compliance verification
- 📋 Comprehensive metrics

---

## Configuration Files

### `.markdownlintrc`
Markdown linting configuration for documentation consistency.

### `deny.toml`
Cargo-deny configuration for dependency security:
- Allowed licenses (MIT, Apache-2.0, BSD, etc.)
- Denied licenses (GPL, AGPL)
- Vulnerability advisory settings
- Registry allow/deny lists

### `.github/CODEOWNERS`
Define code ownership for automatic PR assignments based on:
- File paths
- Components
- Feature areas

---

## Getting Started

### Prerequisites
- GitHub repository with Actions enabled
- Rust 1.70+ (configured in `rust-toolchain.toml`)
- Optional: Codecov account for coverage tracking

### Configuration Steps

1. **Set up Secrets** (if using Docker/Crates.io publishing):
   ```
   CARGO_TOKEN      - API token for crates.io
   DOCKER_USERNAME  - Docker Hub username
   DOCKER_PASSWORD  - Docker Hub password
   ```

2. **Update CODEOWNERS** - Customize `.github/CODEOWNERS` with your team

3. **Enable GitHub Pages** - For automatic doc deployment:
   - Go to Settings → Pages
   - Source: GitHub Actions

4. **Configure Branch Protection**:
   - Require status checks to pass before merging
   - Require code reviews
   - Require CODEOWNERS approval

---

## Workflow Execution Flow

```
Push/PR/Schedule
    ↓
├─ Lint (fast-fail)
│   ├─ Format check
│   └─ Clippy analysis
│
├─ Build (parallel on multiple platforms)
│   ├─ Linux
│   ├─ macOS intel
│   └─ Windows
│
├─ Tests (comprehensive)
│   ├─ Unit tests
│   ├─ Integration tests
│   ├─ Doc tests
│   └─ Feature combinations
│
├─ Security (async)
│   ├─ Vulnerability audit
│   ├─ License check
│   └─ Secret scanning
│
├─ Coverage (if PR)
│   ├─ Tarpaulin
│   └─ LLVM
│
├─ Performance (if tagged release)
│   └─ Benchmarks
│
└─ Results exported to artifacts
```

---

## Usage Examples

### Viewing Workflow Results
1. Go to Actions tab in GitHub
2. Click on workflow run
3. Expand job to see logs
4. Download artifacts for detailed results

### Triggering Manual Workflows
```bash
# Via GitHub CLI
gh workflow run rust.yml --ref main
gh workflow run release.yml --ref main

# Or use GitHub UI: Actions → Select Workflow → Run workflow
```

### Understanding Failure Messages
- **Lint failures**: Run `cargo fmt` and `cargo clippy --fix` locally
- **Test failures**: Check full test output in logs
- **Security warnings**: Review advisories in security.yml output
- **Coverage gaps**: Use `cargo tarpaulin --out Html` locally

---

## Customization

### Adding New Workflows
Create new `.yml` file in `.github/workflows/`:
```yaml
name: Custom Check
on:
  push:
    branches: [ "main" ]

jobs:
  custom-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - # ... your steps
```

### Modifying Job Triggers
Edit the `on:` section in any workflow file:
```yaml
on:
  push:
    branches: [ "main", "develop" ]  # Add branches
  schedule:
    - cron: '0 2 * * *'  # Add schedule
```

### Adjusting Thresholds
- **Coverage gates**: Edit `coverage.yml` coverage percentage targets
- **Clippy warnings**: Adjust `RUSTFLAGS` in `rust.yml`
- **Release checks**: Modify `release.yml` validation steps

---

## Performance Tips

1. **Caching**: Workflows automatically cache cargo registry, git, and build artifacts
2. **Concurrency**: Multiple workflows run in parallel for faster feedback
3. **Job Dependencies**: Tests only run after lint passes (fail-fast strategy)
4. **Artifact Retention**: Set to 30 days for historical analysis

---

## Troubleshooting

### Workflows not triggering
- ✅ Check branch protection rules enabled
- ✅ Verify file paths in workflow triggers match actual files
- ✅ Ensure `.github/workflows/` directory exists

### Slow builds
- ✅ Clear cache in Actions settings
- ✅ Check for large dependencies in Cargo.toml
- ✅ Review build parallelization settings

### Permission errors
- ✅ Verify GitHub token has necessary scopes
- ✅ Check branch protection settings
- ✅ Confirm CODEOWNERS file is valid

### Failed security checks
- ✅ Run `cargo audit` locally to debug
- ✅ Review `deny.toml` allow/deny lists
- ✅ Update vulnerable dependencies

---

## Integration with External Services

### Codecov
- **Auto-upload**: Enabled on coverage.yml
- **Dashboard**: https://codecov.io
- **PR Comments**: Shows coverage changes

### GitHub Security Tab
- **SARIF uploads**: Automatic from security.yml
- **Code scanning**: Shows vulnerabilities by file

### Docker Hub
- **Push on release**: Requires DOCKER credentials
- **Automatic tagging**: Latest + version tags

### Crates.io
- **Publishing**: Requires CARGO_TOKEN secret
- **Stability**: Only on stable releases (no -alpha/-beta/-rc)

---

## Best Practices

1. **Keep workflows DRY**: Use shared actions and reusable workflows
2. **Fail fast**: Lint before building; build before testing
3. **Monitor artifacts**: Review generated reports regularly
4. **Update tools**: Keep cargo-deny, clippy, and other tools current
5. **Security first**: Never commit secrets; use GitHub Secrets
6. **Document changes**: Update this README when modifying workflows

---

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)
- [Similar implementations**: Solana, Ethereum (Rust clients), Polkadot

---

## Next Steps

1. ✅ Update `.github/CODEOWNERS` with your team
2. ✅ Configure secrets for Docker/crates.io if needed
3. ✅ Enable GitHub Pages for documentation
4. ✅ Set up branch protection rules
5. ✅ Test workflows by creating a PR
6. ✅ Review and customize threshold values
7. ✅ Set up Codecov and GitHub Security integrations

---

**Last Updated**: 2026-04-12
**Workflow Status**: All workflows tested and ready for production use
