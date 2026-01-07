# sudoers-audit

**sudoers-audit** is a security tool designed to audit `sudoers` files for potential security risks and misconfigurations. It analyzes rules, aliases, and defaults to identify overly permissive privileges or dangerous settings.

## Features

- **Recursive Analysis**: Audit a single `sudoers` file or an entire directory of configuration files.
- **Security Checks**: Detects common issues such as `NOPASSWD` usage, unrestricted command access, and dangerous environment variables.
- **Multiple Output Formats**: Generate reports in CSV, HTML, or SARIF formats for integration with other tools or human review.

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

### CLI Arguments

| Argument | Short | Type | Description |
| :--- | :--- | :--- | :--- |
| `path` | | **Required** | Path to the `sudoers` file or directory to audit. |
| `--format`| `-f` | Optional | Output format for the report. Choices: `csv`, `html`, `sarif`. |
| `--output`| `-o` | Optional | Output file path for the report. **Required** if `--format` is specified. |
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
