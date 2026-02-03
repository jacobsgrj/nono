# Agent Guide: Working with nono Sandboxes

This document provides instructions for AI agents (like Claude Code, OpenCode, Cursor) on how to diagnose and handle nono sandbox permission denials.

## TL;DR - Quick Rules for Agents

1. **Be Silent**: Don't tell users you detected a sandbox or that you're running diagnostics
2. **React Only**: Only use `nono why` AFTER operations fail, not proactively
3. **Be Concise**: Show 2-3 line error messages, not verbose explanations
4. **Check `NONO_SANDBOXED=1`** before running diagnostics

**Bad (verbose):**
```
I detected NONO_CAP_FILE environment variable, which means I'm running inside
a nono sandbox. Let me run nono why to check if this path is accessible...
```

**Good (concise):**
```
Access denied to /path (not in allowed paths).
To fix: --read /path
```

## Table of Contents

- [Overview](#overview)
- [When to Use `nono why`](#when-to-use-nono-why)
- [Quick Start](#quick-start)
- [Understanding Query Results](#understanding-query-results)
- [Common Scenarios](#common-scenarios)
- [Best Practices](#best-practices)
- [JSON Output Schema](#json-output-schema)

## Overview

When running inside a nono sandbox, file system and network operations may be denied due to security policies. Instead of guessing why an operation failed, use the `nono why` command to get structured explanations and actionable suggestions.

**Key Principles:**
1. **React, don't announce**: Only use `nono why` AFTER an operation fails, not before
2. **Silent diagnostics**: Run `nono why` silently, only show the user the result
3. **No verbose reasoning**: Don't explain to the user that you're checking the sandbox - just do it

## When to Use `nono why`

Use `nono why` **ONLY** when:

1. A file/directory read/write operation fails with "Permission denied" or "Operation not permitted"
2. A network operation fails unexpectedly
3. The user explicitly asks why something is blocked

**DO NOT:**
- Proactively check if you're in a sandbox and tell the user about it
- Explain your diagnostic process to the user
- Run `nono why` before attempting operations (just try the operation first)

**Detection:** Check the `NONO_SANDBOXED` environment variable (set to "1" when active).

```bash
# Silently check if running inside nono (don't show this to users)
if [ "$NONO_SANDBOXED" = "1" ]; then
    # Use nono why when operations fail
fi
```

## Quick Start

### Basic Usage

```bash
# Check if a path is readable
nono why --self --path /tmp/file.txt --op read --json

# Check if a path is writable
nono why --self --path ~/.config/app.json --op write --json

# Check network access
nono why --self --host api.openai.com --port 443 --json
```

**Important Flags:**
- `--self`: Query the current sandbox's capabilities (use this when running inside a sandbox)
- `--json`: Get structured JSON output for programmatic parsing
- `--op`: Operation type (`read`, `write`, or `readwrite`)

### Typical Workflow

1. **Operation fails** with permission error
2. **Run `nono why`** with `--self` and `--json` flags
3. **Parse the JSON** output to understand the denial reason
4. **Communicate findings** to the user with actionable suggestions
5. **Suggest the exact command** to grant the required permission

## Understanding Query Results

### Result Types

The `nono why` command returns one of three statuses:

#### 1. Allowed

The operation would succeed.

```json
{
  "status": "allowed",
  "reason": "explicit_grant",
  "granted_by": "--allow /home/user/project"
}
```

**Reasons:**
- `explicit_grant`: Path was explicitly allowed via CLI flags
- `within_workdir`: Path is within the working directory
- `system_path`: System path allowed for executables
- `network_allowed_by_default`: Network access is enabled

#### 2. Denied

The operation would be blocked.

```json
{
  "status": "denied",
  "reason": "sensitive_path",
  "category": "ssh keys",
  "suggestion": "--read /home/user/.ssh"
}
```

**Denial Reasons:**

- **`sensitive_path`**: The path is in the sensitive paths list (credentials, keys, shell configs)
  - These are blocked by default for security
  - Includes: `~/.ssh`, `~/.aws`, `~/.bashrc`, `~/.zshrc`, etc.
  - User must explicitly grant access with awareness of the risk

- **`not_in_allowed_paths`**: The path is not in the allowed list
  - The path wasn't granted via CLI flags or profile
  - Not necessarily sensitive, just not explicitly allowed

- **`network_blocked`**: Network access is disabled
  - The sandbox was started with `--net-block`

#### 3. Not Sandboxed

Not running inside a nono sandbox.

```json
{
  "status": "not_sandboxed",
  "message": "Not running inside a nono sandbox"
}
```

## Common Scenarios

### Scenario 1: File Read Failed

```bash
# Operation failed: reading ~/.config/app/settings.json
# Step 1: Diagnose
nono why --self --path ~/.config/app/settings.json --op read --json
```

**Example output:**
```json
{
  "status": "denied",
  "reason": "not_in_allowed_paths",
  "suggestion": "--read /home/user/.config/app/settings.json"
}
```

**Agent response to user:**
```
The file read failed because ~/.config/app/settings.json is not in the sandbox's allowed paths.

To fix this, re-run nono with:
  --read ~/.config/app/settings.json
```

### Scenario 2: Sensitive Path Blocked

```bash
# Operation failed: reading ~/.ssh/config
# Step 1: Diagnose
nono why --self --path ~/.ssh/config --op read --json
```

**Example output:**
```json
{
  "status": "denied",
  "reason": "sensitive_path",
  "category": "ssh keys",
  "suggestion": "--read /home/user/.ssh"
}
```

**Agent response to user:**
```
The file read failed because ~/.ssh/config is in the sensitive paths list (category: ssh keys).
This path is blocked by default because it may contain credentials or private keys.

To allow access, re-run nono with:
  --read ~/.ssh

WARNING: Only grant access if you understand the security implications.
```

### Scenario 3: File Write Failed

```bash
# Operation failed: writing to /tmp/output.txt
# Step 1: Diagnose
nono why --self --path /tmp/output.txt --op write --json
```

**Example output:**
```json
{
  "status": "denied",
  "reason": "not_in_allowed_paths",
  "suggestion": "--write /tmp/output.txt"
}
```

**Agent response to user:**
```
The file write failed because /tmp/output.txt is not in the sandbox's allowed paths.

To fix this, re-run nono with:
  --write /tmp
```

### Scenario 4: Network Access Blocked

```bash
# Operation failed: connecting to api.openai.com
# Step 1: Diagnose
nono why --self --host api.openai.com --port 443 --json
```

**Example output:**
```json
{
  "status": "denied",
  "reason": "network_blocked",
  "suggestion": "remove --net-block flag"
}
```

**Agent response to user:**
```
The network connection failed because network access is blocked in this sandbox.

To enable network access, re-run nono WITHOUT the --net-block flag.
```

### Scenario 5: Pre-flight Check (Advanced - Use Sparingly)

In rare cases where you need to check before attempting a HIGH-RISK operation:

```bash
# Before potentially destructive operation
nono why --self --path ~/.bashrc --op write --json
```

**Only use pre-flight checks for:**
- Operations that could corrupt important files
- When the user explicitly asks "can I...?"

**Don't use for:**
- Normal read/write operations (just try them)
- Operations where failure is acceptable

## Best Practices

### 1. Be Silent and Reactive (MOST IMPORTANT)

**DO NOT** explain your diagnostic process to the user. The user doesn't need to know:
- That you detected `NONO_SANDBOXED=1`
- That you're running `nono why` to diagnose
- Your reasoning about path expansion or sandbox mechanics

**ONLY** show the user:
- The fact that the operation failed
- Why it was blocked (one sentence)
- The exact command to fix it

**Bad example (too verbose):**
```
I detected NONO_CAP_FILE, so I'm in a nono sandbox. Let me run
nono why to diagnose. I'm checking if /path/to/file is readable...
```

**Good example (concise):**
```
Access denied to /path/to/file (not in allowed paths).

To fix: --read /path/to/file
```

### 2. Always Use JSON Output

When querying from code, always use `--json` for reliable parsing:

```bash
nono why --self --path /path/to/file --op read --json
```

### 3. Be Specific About Operations

Use the correct `--op` flag:
- `read`: For read operations (cat, grep, open for reading)
- `write`: For write operations (echo >, touch, mkdir, rm)
- `readwrite`: For both (editor, compile output)

### 4. Communicate Clearly But Concisely

When reporting denials to users, be brief:

**Concise template:**
```
Access denied to [path].
Reason: [one sentence explanation]

To fix: [exact flag from suggestion]

[If sensitive_path: one line security warning]
```

**Bad (too verbose):**
```
I've detected that you're running inside a nono sandbox, and I need to
check why the operation failed. Let me run nono why to diagnose...

The operation failed because /path is not in the allowed paths list.
This means that the sandbox was configured without access to this path.

To resolve this issue, you'll need to re-run nono with additional
permissions by adding the --read flag followed by the path...
```

**Good (concise):**
```
Access denied to /path (not in allowed paths).

To fix: --read /path
```

### 5. Handle All Three Result Types

Always check the `status` field and handle:
- `allowed`: Operation should work (if it failed, investigate other causes)
- `denied`: Show user the suggestion
- `not_sandboxed`: The failure is not sandbox-related

### 6. Don't Leak Metadata

nono's `why` command deliberately avoids leaking metadata about denied paths (whether they exist, are files or directories, etc.). Don't circumvent this by running your own checks (like `ls`, `test -f`, etc.) on denied paths.

### 6. Respect Sensitive Path Categories

When `category` is present in a denial, include it in your explanation:

```
This path is blocked because it's in the sensitive paths list.
Category: ssh keys

These paths often contain credentials or private keys.
```

## JSON Output Schema

### Allowed Result

```typescript
{
  "status": "allowed",
  "reason": "explicit_grant" | "within_workdir" | "system_path" | "network_allowed_by_default",
  "granted_by": string  // Description of what granted the permission
}
```

### Denied Result

```typescript
{
  "status": "denied",
  "reason": "sensitive_path" | "not_in_allowed_paths" | "network_blocked",
  "category"?: string,  // Optional: category of sensitive path
  "suggestion": string  // Exact flag to add to allow this operation
}
```

### Not Sandboxed Result

```typescript
{
  "status": "not_sandboxed",
  "message": string
}
```

## Example: Complete Error Handling Flow

```python
import subprocess
import json
import os

def handle_file_access_error(path: str, operation: str):
    """Handle a file access error - silently diagnose and show concise message."""

    # Only check nono if we're sandboxed
    if os.environ.get("NONO_SANDBOXED") != "1":
        return  # Not a nono issue

    # Silently run nono why to diagnose
    result = subprocess.run(
        ["nono", "why", "--self", "--path", path, "--op", operation, "--json"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return  # Can't diagnose, let standard error handling take over

    try:
        query_result = json.loads(result.stdout)
    except json.JSONDecodeError:
        return

    # Show concise message based on result
    if query_result["status"] == "denied":
        reason = query_result["reason"]
        suggestion = query_result["suggestion"]
        category = query_result.get("category")

        # Concise output
        if reason == "sensitive_path":
            print(f"Access denied to {path} (sensitive path: {category}).")
            print(f"To fix: {suggestion}")
            print("WARNING: This path may contain credentials.")
        else:
            print(f"Access denied to {path} (not in allowed paths).")
            print(f"To fix: {suggestion}")

# Usage example
try:
    with open("/home/user/.config/app.json", "r") as f:
        content = f.read()
except PermissionError:
    handle_file_access_error("/home/user/.config/app.json", "read")
    raise  # Re-raise so caller knows it failed
```

**Key points in this example:**
1. Check `NONO_SANDBOXED` first - don't waste time if not sandboxed
2. Run `nono why` silently - don't explain what you're doing
3. Output is concise - 2-3 lines maximum
4. No verbose reasoning about paths or sandbox mechanics

## Environment Variables

When running inside a nono sandbox, the following environment variables are set:

- `NONO_SANDBOXED`: Set to "1" when running inside a nono sandbox
  - Use this for simple boolean detection: `if [ "$NONO_SANDBOXED" = "1" ]`
  - Check this BEFORE running `nono why` to avoid wasted diagnostics

- `NONO_CAP_FILE`: Path to the capability state file (JSON)
  - This file contains the sandbox's capabilities
  - Used internally by `nono why --self` to query current permissions
  - Do not modify or delete this file

**Recommended detection pattern:**
```python
import os

if os.environ.get("NONO_SANDBOXED") == "1":
    # Only use nono why when operations fail
    # Don't announce to the user that you're sandboxed
```

## Advanced Usage

### Query Without Being Sandboxed

You can run `nono why` outside a sandbox to simulate what would happen with specific capabilities:

```bash
# Check if operation would be allowed with --allow .
nono why --path ./src/file.rs --op write --allow .

# Check with profile
nono why --path ~/.config/app.json --op read --profile claude-code --workdir .
```

This is useful for:
- Pre-launch validation
- Testing profiles
- Understanding capability behavior

## Summary

**Golden Rules for Agent Behavior:**

1. **Silent Detection**: Check `NONO_SANDBOXED=1` silently - never announce to users
2. **Reactive Diagnostics**: Only use `nono why` AFTER operations fail, not before
3. **Concise Output**: 2-3 lines maximum - no verbose reasoning
4. **Exact Suggestions**: Show the exact flag from the `suggestion` field
5. **Security Awareness**: Warn about sensitive paths (one line)
6. **No Metadata Leaks**: Don't probe denied paths with ls/test/etc

**Example of perfect agent response:**
```
Access denied to ~/.ssh/config (sensitive path: ssh keys).
To fix: --read ~/.ssh
WARNING: This path may contain credentials.
```

**NOT this:**
```
I've detected the NONO_CAP_FILE environment variable, which indicates
that I'm running inside a nono sandbox. Let me investigate why the
operation failed by running the nono why command to diagnose the
permission issue...
```

By following these guidelines, you provide users with clear, actionable guidance without overwhelming them with diagnostic details.
