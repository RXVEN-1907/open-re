# Contributing to open-re

Thank you for your interest in contributing to open-re! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.78+
- Node.js 20+
- pnpm 9+
- Python 3.11+
- PostgreSQL 16+
- Redis 7+

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re

# Install Rust dependencies
cargo build --workspace

# Install frontend dependencies
cd frontend && pnpm install && cd ..

# Install Python dependencies
cd python && pip install -e . && cd ..

# Start development services
docker compose up -d postgres redis minio

# Run database migrations
cargo run --bin openre-cli -- db migrate
```

## Development Workflow

### 1. Create an Issue

Before starting work, create or find an issue that describes the work to be done. This helps avoid duplicate effort and allows for discussion.

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Use descriptive branch names:
- `feat/add-new-analysis-stage`
- `fix/memory-leak-in-parser`
- `docs/update-installation-guide`
- `refactor/plugin-registry`

### 3. Make Changes

Follow the coding standards below. Make small, focused commits with clear messages.

### 4. Run Tests

```bash
# Rust tests
cargo test --workspace

# Frontend tests
cd frontend && pnpm test

# Python tests
cd python && pytest

# Integration tests
cargo test --test integration_tests
```

### 5. Check Code Quality

```bash
# Rust formatting
cargo fmt --all -- --check

# Rust linting
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Frontend linting
cd frontend && pnpm lint

# Frontend type checking
cd frontend && pnpm typecheck
```

### 6. Submit Pull Request

Push your branch and create a pull request against `main`.

## Pull Request Process

### PR Requirements

- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] No new clippy warnings
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated (for significant changes)
- [ ] Linked to relevant issue(s)

### PR Title Format

Use conventional commit format:

```
feat: add new analysis stage for control flow recovery
fix: resolve memory leak in ELF parser
docs: update installation guide for macOS
refactor: simplify plugin registry implementation
test: add unit tests for incremental analyzer
chore: update dependencies
```

### Review Process

1. Automated checks must pass (CI)
2. At least one maintainer review required
3. Address review comments
4. Maintainer merges after approval

## Coding Standards

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` and `cargo clippy` defaults
- Prefer `anyhow::Result` for application errors
- Use `thiserror` for library error types
- Document public APIs with `///` comments
- Use `#[must_use]` for functions returning important values
- Prefer `async`/`await` over blocking calls
- Use `tokio` for async runtime
- Use `serde` for serialization

### TypeScript/React

- Use functional components with hooks
- Follow [React TypeScript Cheatsheet](https://react-typescript-cheatsheet.netlify.app/)
- Use `zod` for runtime validation
- Prefer `tanstack-query` for server state
- Use `zustand` for client state
- Follow Tailwind CSS conventions
- Use `clsx` + `tailwind-merge` for class names

### Python

- Follow [PEP 8](https://pep8.org/)
- Use type hints everywhere
- Use `pydantic` for data validation
- Follow [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- Use `ruff` for linting
- Use `mypy` for type checking

### Git Conventions

- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Keep commits atomic and focused
- Write descriptive commit messages
- Reference issues: `fixes #123`

## Testing

### Unit Tests

- Place unit tests in the same file as the code (Rust) or `__tests__` directory (TypeScript/Python)
- Test edge cases and error conditions
- Use descriptive test names: `test_function_name_scenario_expected_result`

### Integration Tests

- Place in `tests/` directory
- Test complete workflows
- Use `tempfile` for temporary resources
- Mock external services

### Test Coverage

- Aim for >80% coverage on new code
- Run `cargo llvm-cov` for Rust coverage
- Run `pnpm test --coverage` for frontend coverage

## Documentation

### Code Documentation

- Document all public APIs
- Use `///` for Rust, JSDoc for TypeScript, docstrings for Python
- Include examples for complex functions

### User Documentation

- Update relevant `.md` files in `docs/`
- Keep installation guide current
- Document new features and configuration options

### Architecture Documentation

- Update architecture docs for significant changes
- Document new components and their interactions
- Keep diagrams current

## Community

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: Questions, ideas, announcements
- **Discord**: Real-time chat (invite link in repo description)

### Getting Help

- Check existing issues and discussions first
- Search documentation
- Ask in Discussions or Discord

### Reporting Bugs

Use the bug report template and include:

- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, versions)
- Logs or screenshots if applicable

### Feature Requests

Use the feature request template and include:

- Problem statement
- Proposed solution
- Alternatives considered
- Use cases

## Recognition

Contributors are recognized in:

- [CONTRIBUTORS.md](CONTRIBUTORS.md)
- Release notes
- GitHub contributor graphs

Thank you for contributing to open-re!
4. **Code** - Implementation (Phase 1+ only)
5. **Testing** - Writing tests, reporting bugs, verifying fixes
6. **Community** - Answering questions, reviewing PRs, triaging issues

### Current Phase: Phase 0 - Research & Documentation

**Important**: We are currently in Phase 0. No implementation code should be written yet. Contributions should focus on:

- Researching existing reverse engineering tools
- Writing and improving documentation
- Defining requirements and specifications
- Creating architecture proposals
- Identifying risks and mitigation strategies

## Development Process

### Branching Strategy

- `main` - Stable, reviewed documentation only
- `develop` - Ongoing documentation work
- `feature/*` - Feature-specific documentation branches
- `research/*` - Research and analysis branches

### Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types: `docs`, `research`, `design`, `feat`, `fix`, `refactor`, `test`, `chore`

Examples:
```
docs(vision): add mission statement and core philosophy
research(competitors): analyze Ghidra's plugin architecture
design(architecture): propose plugin system interface
```

## Pull Request Guidelines

### Before Submitting

1. Ensure your branch is up to date with `develop`
2. Run any documentation linting/formatting tools
3. Verify all links work
4. Check for spelling/grammar errors

### PR Requirements

- Clear title following conventional commits
- Description explaining the change and rationale
- Reference related issues
- No implementation code (Phase 0)
- Documentation follows project style guide

### Review Process

1. Automated checks (link validation, formatting)
2. Maintainer review for content quality
3. Community feedback period (48 hours minimum)
4. Approval from at least one maintainer
5. Merge to `develop` branch

## Issue Reporting

### Bug Reports (Documentation)

Use the bug report template for:
- Broken links
- Factual errors
- Unclear explanations
- Missing information

### Feature Requests

Use the feature request template for:
- New documentation sections
- Research topics to explore
- Process improvements

### Research Tasks

Use the research task template for:
- Tool analysis assignments
- Technology evaluations
- Architecture comparisons

## Documentation Standards

### Writing Style

- Clear, concise, professional tone
- Active voice preferred
- Define acronyms on first use
- Use inclusive language
- Avoid jargon without explanation

### Formatting

- Markdown with consistent heading levels
- Code blocks with language specification
- Tables for structured comparisons
- Diagrams using Mermaid syntax where helpful
- Relative links for internal references

### Structure

Each document should have:
- Clear title and purpose
- Table of contents for long documents
- Introduction/summary
- Detailed content organized logically
- Conclusion or next steps
- References/sources

## Testing

### Documentation Testing

- All internal links must resolve
- External links should be accessible
- Code examples (if any) should be syntactically correct
- Diagrams should render correctly

### Future Code Testing (Phase 1+)

- Unit tests for all new functionality
- Integration tests for major features
- Performance benchmarks for critical paths
- Security testing for analysis features

## Community

### Communication Channels

- **GitHub Discussions** - General questions, ideas, announcements
- **GitHub Issues** - Bug reports, feature requests, tasks
- **Pull Requests** - Code/documentation reviews

### Getting Help

- Check existing documentation first
- Search closed issues and discussions
- Ask in GitHub Discussions for general questions
- Tag maintainers for urgent matters

### Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project website (future)
- Annual contributor highlights

## Legal

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

## Questions?

Open a GitHub Discussion or contact the maintainers directly.

---

*This document is a living document and will evolve as the project progresses through phases.*