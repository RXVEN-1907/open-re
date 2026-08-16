# Pull Request

## Description

Brief description of changes.

## Type of Change

- [ ] Security check (new detection)
- [ ] Bug fix
- [ ] Feature (CLI, output, AI, etc.)
- [ ] Refactoring (no behavior change)
- [ ] Documentation update
- [ ] Tests
- [ ] CI/CD
- [ ] Dependencies
- [ ] Other: ___________

## Related Issues

Closes #(issue number)
Relates to #(issue number)

## Changes Made

- Change 1
- Change 2
- Change 3

## Checklist

### Code Quality
- [ ] All tests pass (`cargo test -p openre-scan`)
- [ ] Code formatted (`cargo fmt --all -- --check`)
- [ ] Zero clippy warnings (`cargo clippy -p openre-scan -- -D warnings`)
- [ ] Release build succeeds (`cargo build --release -p openre-scan`)

### If Adding a Security Check
- [ ] Check module in `crates/openre-scan/src/checks/`
- [ ] Implements `Check` trait with `name()` and `run()`
- [ ] Registered in `checks/mod.rs`
- [ ] Added to appropriate scan profile(s) in `get_all_checks()`
- [ ] Integration test added in `tests/integration.rs`
- [ ] Evidence included in findings
- [ ] Remediation guidance included
- [ ] Appropriate severity and confidence

### If Changing CLI
- [ ] Help text updated (`--help` shows new option)
- [ ] Integration test for new CLI behavior
- [ ] Documentation updated (README, INSTALLATION_GUIDE)

### Documentation
- [ ] CHANGELOG.md updated (for user-facing changes)
- [ ] README.md updated (if new feature)
- [ ] Code comments for complex logic

### Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual test: `./target/release/openre-scan scan https://example.com --profile standard`

## Screenshots/Previews

If applicable, add screenshots of:
- CLI output changes
- New findings
- TUI changes

## Additional Notes

Any additional information for reviewers.