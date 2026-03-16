# Contributing to SRMTA

Thank you for your interest in contributing to SRMTA! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Running Tests](#running-tests)
- [Areas Where Help Is Needed](#areas-where-help-is-needed)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## Getting Started

1. **Fork the repository** at [https://github.com/rushikeshsakharleofficial/SRMTA](https://github.com/rushikeshsakharleofficial/SRMTA).

2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/<your-username>/SRMTA.git
   cd SRMTA
   ```

3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/rushikeshsakharleofficial/SRMTA.git
   ```

4. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

5. **Make your changes**, commit them, and push to your fork:
   ```bash
   git push origin feat/your-feature-name
   ```

6. **Open a Pull Request** against the `main` branch of the upstream repository.

## Development Setup

### Prerequisites

- Go 1.21 or later
- Node.js 18 or later (for the admin API)
- A running Postfix or similar MTA for integration testing (optional)
- Make

### Building

```bash
make build
```

### Running locally

```bash
# Start the MTA
./srmta -config configs/srmta.yml

# Start the admin API
cd web/api
npm install
node src/server.js
```

## How to Contribute

### Reporting Bugs

Use the [Bug Report](https://github.com/rushikeshsakharleofficial/SRMTA/issues/new?template=bug_report.md) issue template. Include as much detail as possible: steps to reproduce, expected vs. actual behavior, and your environment.

### Suggesting Features

Use the [Feature Request](https://github.com/rushikeshsakharleofficial/SRMTA/issues/new?template=feature_request.md) issue template. Describe the problem you are trying to solve and your proposed solution.

### Submitting Pull Requests

1. Ensure your branch is up to date with `main`:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```
2. Follow the [code style](#code-style) guidelines.
3. Write or update tests for your changes.
4. Fill out the PR template completely.
5. Keep PRs focused -- one feature or fix per PR.

## Code Style

### Go

- All Go code must be formatted with `gofmt`. Run it before committing:
  ```bash
  gofmt -w .
  ```
- Follow the conventions in [Effective Go](https://go.dev/doc/effective_go).
- Use `golint` and `go vet` to catch common issues:
  ```bash
  go vet ./...
  golint ./...
  ```

### JavaScript (Admin API)

- All JavaScript code must pass ESLint. The project includes an ESLint configuration:
  ```bash
  cd web/api
  npx eslint src/
  ```
- Use `const` and `let` (never `var`).
- Use async/await over raw Promises where possible.

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Every commit message must follow this format:

```
<type>(<scope>): <short summary>

<optional body>

<optional footer>
```

### Types

| Type       | Description                                      |
|------------|--------------------------------------------------|
| `feat`     | A new feature                                    |
| `fix`      | A bug fix                                        |
| `docs`     | Documentation only changes                       |
| `style`    | Code style changes (formatting, no logic change) |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf`     | Performance improvement                          |
| `test`     | Adding or updating tests                         |
| `build`    | Build system or dependency changes               |
| `ci`       | CI/CD configuration changes                      |
| `chore`    | Other changes that don't modify src or test files|

### Scope

Use the relevant module name: `smtp`, `queue`, `compliance`, `config`, `api`, `ui`, `deploy`.

### Examples

```
feat(smtp): add STARTTLS enforcement option
fix(queue): prevent duplicate delivery on retry
docs(api): document authentication endpoints
test(compliance): add SPF validation unit tests
```

## Running Tests

### Go tests

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test -v ./internal/smtp/...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### JavaScript tests (Admin API)

```bash
cd web/api
npm test
```

## Areas Where Help Is Needed

We actively welcome contributions in the following areas:

- **Database-backed authentication** -- The admin API currently has a TODO placeholder for authentication in `server.js`. We need a proper implementation backed by PostgreSQL or SQLite with password hashing (bcrypt/argon2) and session/JWT management.

- **DMARC record lookup integration** -- Implement DNS-based DMARC record lookup and policy evaluation as part of the inbound compliance checks.

- **SPF validation improvements** -- The current SPF validation needs hardening: proper handling of nested includes, redirect modifiers, and macro expansion per RFC 7208.

- **Redis-based DNS caching** -- Add an optional Redis-backed DNS cache layer to reduce lookup latency and external DNS query volume under high throughput.

- **Dashboard improvements (React/Vue migration)** -- The current admin UI is basic HTML/JS. We want to migrate it to a modern framework (React or Vue) with proper state management and a responsive layout.

- **Unit test coverage** -- Many packages have minimal or no test coverage. Adding tests for `internal/smtp`, `internal/queue`, `internal/compliance`, and `internal/config` is highly valuable.

- **Documentation** -- Improve inline code documentation, add architecture diagrams, write deployment guides for various platforms, and expand the API reference.

- **Packaging for Alpine/Arch Linux** -- We have .deb and .rpm packaging. Adding APKBUILD (Alpine) and PKGBUILD (Arch Linux) packaging would broaden distribution support.

If you want to work on any of these, please open an issue first to discuss your approach so we can avoid duplicated effort.

## Questions?

If you have questions about contributing, feel free to open a [Discussion](https://github.com/rushikeshsakharleofficial/SRMTA/discussions) or reach out to the maintainers.
