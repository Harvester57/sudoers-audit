# sudoers-audit

**sudoers-audit** is a security tool designed to audit `sudoers` files for potential security risks and misconfigurations. It analyzes rules, aliases, and defaults to identify overly permissive privileges or dangerous settings.

## Features

- **Recursive Analysis**: Audit a single `sudoers` file or an entire directory of configuration files.
- **Security Checks**: Detects common issues such as `NOPASSWD` usage, unrestricted command access (`ALL`), and dangerous environment variables (`env_keep`).
- **Hardening Verification**: Checks for hardening rules including wildcard abuse, Privilege Scope violations, `!authenticate` settings, and more.
- **Filesystem Permissions**: Optionally verifies that sudoers configuration files are owned by root and not writable by others (requires running on the target system).
- **Multiple Output Formats**: Generate reports in CSV, HTML, or SARIF formats.

## Installation

You can install `sudoers-audit` using standard Python package managers.

```bash
pip install .
```

Or using `uv` if you are in a developing environment:

```bash
uv sync
```

## Usage

The basic usage requires providing the path to a `sudoers` file or a directory containing them.

```bash
sudoers-audit <path> [options]
```

## Docker usage

You can also run `sudoers-audit` using Docker.

### Pulling from GitHub Container Registry

To use the pre-built image:

```bash
docker pull ghcr.io/harvester57/sudoers-audit:latest
docker run --rm -v $(pwd):/data ghcr.io/harvester57/sudoers-audit:latest /etc/sudoers
```

### Building locally

To build the image locally:

```bash
docker build -t sudoers-audit .
docker run --rm -v $(pwd):/data sudoers-audit /etc/sudoers
```

### CLI Arguments

| Argument | Short | Type | Description |
| :--- | :--- | :--- | :--- |
| `path` | | **Required** | Path to the `sudoers` file or directory to audit. |
| `--format`| `-f` | Optional | Output format for the report. Choices: `csv`, `html`, `sarif`. |
| `--output`| `-o` | Optional | Output file path for the report. **Required** if `--format` is specified. |
| `--check-permissions`| `-p` | Flag | Enable filesystem permission checks (ownership/write permissions). **Requires execution on the target system.** |
| `--help` | `-h` | Flag | Show the help message and exit. |

### Examples

**Audit a single file and print findings to stdout:**

```bash
sudoers-audit /etc/sudoers
```

**Audit a directory:**

```bash
sudoers-audit /etc/sudoers.d/
```

**Generate an HTML report:**

```bash
sudoers-audit /etc/sudoers -f html -o audit_report.html
```

**Generate a SARIF report for CI/CD integration:**

```bash
sudoers-audit . -f sarif -o results.sarif
```

## Requirements

- Python 3.13+
