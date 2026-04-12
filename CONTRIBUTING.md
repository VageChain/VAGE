# Contributing to VAGE

Welcome to the VAGE blockchain project! This guide explains how to contribute and how our automated workflows ensure code quality and security.

## Development Workflow

### 1. Fork and Clone
```bash
git clone https://github.com/YOUR_USERNAME/vage.git
cd vage
cd vage  # enter the main crate directory
```

### 2. Create a Feature Branch
```bash
git checkout -b feature/descriptive-name
# or
git checkout -b fix/issue-description
```

### 3. Local Development

#### Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
```

#### Build the Project
```bash
cd vage
cargo build
```

#### Run Tests Locally
```bash
# Run all tests
cargo test --all

# Run specific tests
cargo test consensus_tests

# Run with output
cargo test -- --nocapture

# Run benchmarks locally
cargo bench
```

#### Code Formatting
```bash
# Format code
cargo fmt --all

# Check formatting without changing
cargo fmt --all -- --check

# Format with clippy fixes
cargo clippy --fix --allow-dirty
```

### 4. Before Pushing

Run these checks locally to catch issues early:

```bash
# Format check
cargo fmt --all -- --check

# Clippy analysis
cargo clippy --workspace --all-targets -- -D warnings

# Full test suite
cargo test --all --verbose

# Security audit
cargo audit

# Doc tests
cargo test --doc
```

### 5. Commit Guidelines

Write clear, descriptive commit messages:

```
feat: Add parallel execution engine
fix: Resolve consensus deadlock in validator sync
docs: Update RPC API documentation
refactor: Simplify state tree traversal
test: Add integration tests for mempool

Format: <type>(<scope>): <subject>

Types:
  - feat: New feature
  - fix: Bug fix
  - docs: Documentation change
  - refactor: Code refactor (no feature change)
  - perf: Performance improvement
  - test: Test addition/modification
  - ci: CI/CD workflow changes
  - chore: Dependencies, tooling, etc.
```

### 6. Push and Open Pull Request

```bash
git push origin feature/descriptive-name
```

Then create a PR on GitHub with:
- Clear title describing the change
- Detailed description of motivations and changes
- Reference any related issues (#123)
- Link to relevant documentation

## Automated Checks

### On Every Pull Request

When you open a PR, the following checks automatically run:

#### 🔍 Code Quality (30-60 seconds)
- ✅ **Formatting** - `cargo fmt` compliance
- ✅ **Linting** - Clippy warnings/errors
- ⏱️ **Compilation** - Builds on Linux, macOS, Windows

#### 🧪 Testing (2-5 minutes)
- ✅ **Unit tests** - All isolated component tests
- ✅ **Integration tests** - Full stack tests
- ✅ **Doc tests** - Documentation examples
- ✅ **Feature tests** - Different feature combinations

#### 🔒 Security (1-2 minutes)
- ✅ **Dependency audit** - Known vulnerabilities
- ✅ **License check** - Legal compliance
- ✅ **Code quality scanning** - SARIF reports

#### 📊 Code Coverage (1-2 minutes)
- ✅ **Line coverage** - Target 75%+
- ✅ **Branch coverage** - Target 70%+
- ✅ **Coverage report** - PR comment with changes

**Total time**: ~5-10 minutes for full feedback

### Status Requirements

All checks must pass before merge:
```
✓ ci/github/rust.yml (lint + build + test + features)
✓ ci/github/security.yml 
✓ ci/github/coverage.yml
```

Green checkmarks = Ready for review! ✅

## Review Process

### Code Review Guidelines

1. **Reviewer Assignment**
   - Assigned based on `CODEOWNERS`
   - Can request specific reviewers
   - Must address all requested changes

2. **Review Checklist**
   ```
   - [ ] Code follows style guidelines
   - [ ] New tests added
   - [ ] Documentation updated
   - [ ] No new warnings introduced
   - [ ] Security checks pass
   - [ ] Performance impact acceptable
   ```

3. **Feedback Loop**
   - Address comments with new commits (don't force-push during review)
   - Re-request review when ready
   - Automation re-runs on each push

### Merging PRs

Once approved:
1. All automated checks passing ✅
2. At least one approval from CODEOWNERS
3. No merge conflicts
4. Branch protection rules satisfied

Click "Squash and merge" or "Rebase and merge" based on project preference.

## Testing Guidelines

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Arrange
        let input = vec![1, 2, 3];
        
        // Act
        let result = process(input);
        
        // Assert
        assert_eq!(result, vec![2, 4, 6]);
    }

    #[test]
    #[should_panic(expected = "invalid input")]
    fn test_invalid_input() {
        let invalid = vec![];
        process(invalid);
    }

    #[tokio::test]
    async fn test_async_operation() {
        let result = async_func().await;
        assert!(result.is_ok());
    }
}
```

### Coverage Requirements

- **New features**: Aim for 80%+ coverage on new code
- **Bug fixes**: Include test demonstrating the fix
- **Refactoring**: Maintain or improve existing coverage

Run coverage locally:
```bash
# Using tarpaulin
cargo tarpaulin --out Html

# Using llvm-cov
cargo llvm-cov --html
```

## Performance Considerations

### Benchmark Changes

If your change affects performance:

1. **Add benchmark**:
```rust
#[bench]
fn bench_consensus(b: &mut Bencher) {
    let consensus = setup_consensus();
    b.iter(|| consensus.process_block(block.clone()));
}
```

2. **Run locally**:
```bash
cargo bench --bench consensus_bench
```

3. **Document in PR**:
- Expected performance impact
- Benchmarks showing improvement/regression
- Analyzed trade-offs

3. **Automated checks**:
   - Benchmarks run on main branch
   - PR benchmarks compared to baseline
   - Results linked in PR comment

## Documentation Requirements

### When to Document

- **New public APIs**: Always document with doc comments
- **Complex algorithms**: Explain the approach
- **Configuration options**: Document all settings
- **Breaking changes**: Update guides and examples

### Documentation Format

```rust
/// Brief one-line summary
///
/// More detailed explanation of what this does, why,
/// and when to use it.
///
/// # Examples
///
/// ```
/// let result = my_function(input);
/// assert_eq!(result, expected);
/// ```
///
/// # Panics
///
/// Panics if input is invalid.
///
/// # Errors
///
/// Returns error if operation fails.
pub fn my_function(input: &str) -> Result<Output> {
    // ...
}
```

Run doc tests:
```bash
cargo test --doc
```

## Common Issues

### ❌ "Formatting check failed"
```bash
# Fix locally first
cargo fmt --all

# Then commit
git add .
git commit --amend
git push --force-with-lease
```

### ❌ "Clippy warnings detected"
```bash
# See warnings
cargo clippy --all-targets

# Fix automatically
cargo clippy --fix --allow-dirty

# Manual review and commit
git add .
git commit -m "fix: Address clippy warnings"
```

### ❌ "Test failed: xyz"
```bash
# Run locally
cargo test xyz -- --nocapture

# Fix and commit
```

### ❌ "Coverage below threshold"
```bash
# Check coverage
cargo tarpaulin --out Html

# Add missing tests
# Then commit and re-push
```

### ❌ "Dependency conflicts"
```bash
# Update lockfile
cargo update

# Or resolve manually in Cargo.toml
cargo check
```

## Release Process

### Version Numbering (Semantic Versioning)

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (1.1.0): New features, backward compatible
- **PATCH** (1.0.1): Bug fixes only

### Creating a Release

1. **Update version** in `vage/Cargo.toml`:
```toml
[package]
version = "1.2.0"  # Update this
```

2. **Create tag**:
```bash
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```

3. **Automated actions**:
   - ✅ Workflow validates version format
   - ✅ Builds binaries (Linux, macOS, Windows)
   - ✅ Generates changelog
   - ✅ Creates GitHub release
   - ✅ Publishes to crates.io
   - ✅ Builds Docker image

4. **Verify release**:
   - GitHub: https://github.com/vage/releases/tag/v1.2.0
   - Crates.io: https://crates.io/crates/vage-node

## Getting Help

- **Questions?** Open a GitHub discussion
- **Bug report?** Use issue template with reproduction steps
- **Security issue?** Email security@example.com (don't use issues)
- **Need review?** Tag specific experts or use @vage/core-team

## Code of Conduct

- Be respectful and inclusive
- Assume good intentions
- Focus on the code, not the person
- Help others learn
- Report violations to maintainers

## Resources

- [Rust Book](https://doc.rust-lang.org/book/) - Learn Rust
- [Cargo Guide](https://doc.rust-lang.org/cargo/) - Build tool
- [API Docs](https://docs.vage.example.io) - Project documentation
- [Architecture](../docs/architecture.md) - System design
- [Consensus](../docs/consensus.md) - HotStuff + FastPath

## Acknowledgments

Thank you for contributing to VAGE! Every contribution helps improve the blockchain ecosystem. 🙏

---

**Happy coding!** 🚀

For questions about this guide, open an issue or discussion.
