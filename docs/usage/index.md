# Usage Overview

nono wraps any command with an OS-level sandbox. You specify what the command is allowed to access, and nono enforces those restrictions at the kernel level.

## Basic Syntax

```bash
nono [OPTIONS] -- <COMMAND> [ARGS...]
```

The `--` separator is required. Everything after it is the command to run.

## Minimal Example

```bash
# Grant read+write access to current directory, run claude
nono --allow . -- claude
```

## Understanding Permissions

nono provides three levels of filesystem access:

| Flag | Access Level | Use Case |
|------|--------------|----------|
| `--allow` / `-a` | Read + Write | Working directories, project folders |
| `--read` / `-r` | Read Only | Source code, configuration |
| `--write` / `-w` | Write Only | Output directories, logs |

### Directory vs File Permissions

- **Directory flags** (`--allow`, `--read`, `--write`) grant recursive access
- **File flags** (`--allow-file`, `--read-file`, `--write-file`) grant access to a single file

```bash
# Recursive access to entire directory
nono --allow ./project -- command

# Access to single config file only
nono --read-file ./config.toml -- command
```

## Network Access

Network is **allowed by default**. Use `--net-block` to disable outbound connections:

```bash
# Block network access for offline build
nono --allow . --net-block -- cargo build
```

!!! note "Binary Control"
    Network access is currently all-or-nothing. You can either allow all network access (default) or block it entirely with `--net-block`.

    Granular filtering (allowing only specific domains) is not yet supported due to technical limitations in Apple Seatbelt and requires experimentation. This feature may be added in a future release.

## What Happens at Runtime

1. **Parse** - nono parses your capability flags
2. **Canonicalize** - All paths are resolved to absolute paths (prevents symlink escapes)
3. **Apply Sandbox** - Kernel sandbox is initialized (irreversible)
4. **Execute** - nono exec()s into your command, inheriting the sandbox
5. **Enforce** - Kernel blocks any unauthorized access attempts

## Environment Variables

When running inside nono, these environment variables are set:

| Variable | Description |
|----------|-------------|
| `NONO_ACTIVE` | Set to `1` when running under nono |
| `NONO_ALLOWED` | Colon-separated list of allowed paths |
| `NONO_NET` | `allowed` or `blocked` |
| `NONO_BLOCKED` | Colon-separated list of blocked sensitive paths |
| `NONO_HELP` | Help text for requesting additional access |

These help sandboxed applications provide better error messages.

## Next Steps

- [CLI Reference](flags.md) - Complete flag documentation
- [Examples](examples.md) - Common usage patterns
