//! Query API for checking if operations would be allowed
//!
//! This module provides the Advisory API that lets agents pre-check if operations
//! will be allowed before attempting them. When an agent encounters a permission
//! error, it can call `nono query` to get a structured JSON response explaining
//! why and how to fix it.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::capability::{CapabilitySet, FsAccess};
use crate::config;
use crate::error::{NonoError, Result};

/// Result of a query operation
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status")]
pub enum QueryResult {
    /// Operation would be allowed
    #[serde(rename = "allowed")]
    Allowed {
        /// Why it's allowed
        reason: AllowReason,
        /// What granted the permission
        granted_by: String,
    },
    /// Operation would be denied
    #[serde(rename = "denied")]
    Denied {
        /// Why it's denied
        reason: DenyReason,
        /// Category of sensitive path (if applicable)
        #[serde(skip_serializing_if = "Option::is_none")]
        category: Option<String>,
        /// Suggested flag to allow this operation
        suggestion: String,
    },
    /// Not running inside a nono sandbox
    #[serde(rename = "not_sandboxed")]
    NotSandboxed {
        /// Explanation message
        message: String,
    },
}

/// Reason why an operation is allowed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AllowReason {
    /// Explicitly granted via --allow, --read, or --write
    ExplicitGrant,
    /// Within the working directory ($WORKDIR)
    WithinWorkdir,
    /// System path allowed for executables
    SystemPath,
    /// Network allowed by default
    NetworkAllowedByDefault,
}

/// Reason why an operation is denied
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Path is in the sensitive paths list
    SensitivePath,
    /// Path is not in the list of allowed paths
    NotInAllowedPaths,
    /// Network access is blocked
    NetworkBlocked,
}

/// Query if a path operation would be allowed
///
/// Checks the path against:
/// 1. Sensitive paths list (always denied unless explicitly overridden)
/// 2. Granted capabilities from CLI args or profile
///
/// # Errors
/// Returns `NonoError::EnvVarValidation` if tilde expansion is needed but HOME is missing or invalid
pub fn query_path(path: &Path, op: FsAccess, caps: &CapabilitySet) -> Result<QueryResult> {
    let path_str = path.display().to_string();

    // First check sensitive paths - these are blocked by default
    if let Some(category) = config::check_sensitive_path(&path_str) {
        return Ok(QueryResult::Denied {
            reason: DenyReason::SensitivePath,
            category: Some(category.to_string()),
            // SECURITY: Do not call path.is_file() here - it leaks metadata about denied paths
            // (reveals whether path exists and its type). Always use directory-level flags.
            suggestion: suggest_flag(path, op),
        });
    }

    // Expand ~ in path for comparison
    // SECURITY: Validate HOME environment variable before use
    // Per security guidelines: "Validate environment variables before use.
    // Never assume HOME, TMPDIR, or other env vars are set or trustworthy."
    let expanded_path_str = if path_str.starts_with("~/") || path_str == "~" {
        let home = std::env::var("HOME").map_err(|_| NonoError::EnvVarValidation {
            var: "HOME".to_string(),
            reason: "not set (required for tilde expansion)".to_string(),
        })?;

        // Validate HOME is an absolute path
        if !Path::new(&home).is_absolute() {
            return Err(NonoError::EnvVarValidation {
                var: "HOME".to_string(),
                reason: format!("must be an absolute path, got: {}", home),
            });
        }

        if path_str.starts_with("~/") {
            path_str.replacen('~', &home, 1)
        } else {
            home
        }
    } else {
        path_str.clone()
    };

    // Convert to Path for secure component-based comparison
    // SECURITY: Using Path::starts_with() instead of String::starts_with()
    // to prevent path traversal attacks like "/homeevil" matching "/home"
    let expanded_path = Path::new(&expanded_path_str);
    let query_path = Path::new(&path_str);

    // Check against granted capabilities
    for cap in &caps.fs {
        // Check if the path matches or is under the capability path
        // SECURITY: Path::starts_with() compares path components, not strings
        // e.g., Path("/homeevil").starts_with("/home") == false
        //       String "/homeevil".starts_with("/home") == true (VULNERABLE!)
        let matches = if cap.is_file {
            // File capability - exact match only
            expanded_path == cap.resolved
        } else {
            // Directory capability - path is under this directory
            // Check both resolved (canonicalized) and original paths
            expanded_path == cap.resolved
                || expanded_path.starts_with(&cap.resolved)
                || query_path == cap.original
                || query_path.starts_with(&cap.original)
        };

        if matches && access_allows(&cap.access, op) {
            return Ok(QueryResult::Allowed {
                reason: AllowReason::ExplicitGrant,
                granted_by: format!(
                    "--{} {}",
                    access_to_flag(&cap.access),
                    cap.original.display()
                ),
            });
        }
    }

    // Not allowed
    Ok(QueryResult::Denied {
        reason: DenyReason::NotInAllowedPaths,
        category: None,
        // SECURITY: Do not call path.is_file() here - it leaks metadata about denied paths
        suggestion: suggest_flag(path, op),
    })
}

/// Query if network access would be allowed
pub fn query_network(_host: &str, _port: u16, caps: &CapabilitySet) -> QueryResult {
    if caps.net_block {
        QueryResult::Denied {
            reason: DenyReason::NetworkBlocked,
            category: None,
            suggestion: "remove --net-block flag".to_string(),
        }
    } else {
        QueryResult::Allowed {
            reason: AllowReason::NetworkAllowedByDefault,
            granted_by: "network allowed by default".to_string(),
        }
    }
}

/// Check if a capability's access level allows the requested operation
fn access_allows(cap_access: &FsAccess, requested: FsAccess) -> bool {
    match (cap_access, requested) {
        // ReadWrite allows anything
        (FsAccess::ReadWrite, _) => true,
        // Read allows Read
        (FsAccess::Read, FsAccess::Read) => true,
        // Write allows Write
        (FsAccess::Write, FsAccess::Write) => true,
        // Otherwise denied
        _ => false,
    }
}

/// Convert access level to CLI flag name
fn access_to_flag(access: &FsAccess) -> &'static str {
    match access {
        FsAccess::Read => "read",
        FsAccess::Write => "write",
        FsAccess::ReadWrite => "allow",
    }
}

/// Generate a suggestion for how to allow an operation
///
/// SECURITY: This function deliberately does NOT check if the path is a file or directory
/// to avoid metadata leaks. Calling path.is_file() on denied paths would reveal whether
/// they exist and their type, violating the security principle:
/// "Metadata leaks: Even denying file content, allowing metadata reveals file existence"
///
/// We always suggest directory-level flags (--read, --write, --allow) which work for
/// both files and directories, preventing information disclosure about denied paths.
fn suggest_flag(path: &Path, op: FsAccess) -> String {
    let flag = match op {
        FsAccess::Read => "--read",
        FsAccess::Write => "--write",
        FsAccess::ReadWrite => "--allow",
    };
    format!("{} {}", flag, path.display())
}

/// Print a query result in human-readable format
pub fn print_result(result: &QueryResult) {
    match result {
        QueryResult::Allowed { reason, granted_by } => {
            println!("ALLOWED");
            println!("  Reason: {:?}", reason);
            println!("  Granted by: {}", granted_by);
        }
        QueryResult::Denied {
            reason,
            category,
            suggestion,
        } => {
            println!("DENIED");
            println!("  Reason: {:?}", reason);
            if let Some(cat) = category {
                println!("  Category: {}", cat);
            }
            println!("  Suggestion: {}", suggestion);
        }
        QueryResult::NotSandboxed { message } => {
            println!("NOT SANDBOXED");
            println!("  {}", message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_sensitive_path() {
        let caps = CapabilitySet::default();
        let result = query_path(Path::new("~/.ssh/id_rsa"), FsAccess::Read, &caps)
            .expect("query should succeed");

        match result {
            QueryResult::Denied {
                reason: DenyReason::SensitivePath,
                category: Some(_),
                ..
            } => {}
            _ => panic!("Expected sensitive path denial, got {:?}", result),
        }
    }

    #[test]
    fn test_query_not_allowed_path() {
        let caps = CapabilitySet::default();
        let result = query_path(Path::new("/tmp/some/file"), FsAccess::Read, &caps)
            .expect("query should succeed");

        match result {
            QueryResult::Denied {
                reason: DenyReason::NotInAllowedPaths,
                category: None,
                ..
            } => {}
            _ => panic!("Expected not-in-allowed-paths denial, got {:?}", result),
        }
    }

    #[test]
    fn test_query_network_allowed() {
        let caps = CapabilitySet::default();
        let result = query_network("api.openai.com", 443, &caps);

        match result {
            QueryResult::Allowed {
                reason: AllowReason::NetworkAllowedByDefault,
                ..
            } => {}
            _ => panic!("Expected network allowed, got {:?}", result),
        }
    }

    #[test]
    fn test_query_network_blocked() {
        let caps = CapabilitySet {
            net_block: true,
            ..Default::default()
        };

        let result = query_network("api.openai.com", 443, &caps);

        match result {
            QueryResult::Denied {
                reason: DenyReason::NetworkBlocked,
                ..
            } => {}
            _ => panic!("Expected network blocked, got {:?}", result),
        }
    }

    #[test]
    fn test_access_allows() {
        // ReadWrite allows anything
        assert!(access_allows(&FsAccess::ReadWrite, FsAccess::Read));
        assert!(access_allows(&FsAccess::ReadWrite, FsAccess::Write));
        assert!(access_allows(&FsAccess::ReadWrite, FsAccess::ReadWrite));

        // Read only allows Read
        assert!(access_allows(&FsAccess::Read, FsAccess::Read));
        assert!(!access_allows(&FsAccess::Read, FsAccess::Write));
        assert!(!access_allows(&FsAccess::Read, FsAccess::ReadWrite));

        // Write only allows Write
        assert!(access_allows(&FsAccess::Write, FsAccess::Write));
        assert!(!access_allows(&FsAccess::Write, FsAccess::Read));
        assert!(!access_allows(&FsAccess::Write, FsAccess::ReadWrite));
    }

    #[test]
    fn test_suggest_flag() {
        // SECURITY: All suggestions use directory-level flags to avoid metadata leaks
        assert_eq!(
            suggest_flag(Path::new("./src"), FsAccess::Read),
            "--read ./src"
        );
        assert_eq!(
            suggest_flag(Path::new("./file.txt"), FsAccess::Write),
            "--write ./file.txt"
        );
        assert_eq!(
            suggest_flag(Path::new("./dir"), FsAccess::ReadWrite),
            "--allow ./dir"
        );
    }

    /// SECURITY REGRESSION TEST
    /// Ensures Path::starts_with() is used instead of String::starts_with()
    /// to prevent path traversal attacks.
    ///
    /// With string comparison: "/homeevil".starts_with("/home") == true (VULNERABLE!)
    /// With path comparison:   Path("/homeevil").starts_with("/home") == false (SECURE)
    #[test]
    fn test_path_component_comparison_security() {
        use crate::capability::FsCapability;
        use std::path::PathBuf;

        // Create a capability for /home
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/home"),
            resolved: PathBuf::from("/home"),
            access: FsAccess::ReadWrite,
            is_file: false,
        });

        // /home/user should be allowed (legitimate child path)
        let result = query_path(Path::new("/home/user"), FsAccess::Read, &caps)
            .expect("query should succeed");
        assert!(
            matches!(result, QueryResult::Allowed { .. }),
            "Expected /home/user to be allowed under /home capability"
        );

        // /homeevil should NOT be allowed (not a child, just similar prefix)
        // This is the security vulnerability we're preventing
        let result = query_path(Path::new("/homeevil"), FsAccess::Read, &caps)
            .expect("query should succeed");
        assert!(
            matches!(
                result,
                QueryResult::Denied {
                    reason: DenyReason::NotInAllowedPaths,
                    ..
                }
            ),
            "SECURITY VULNERABILITY: /homeevil should NOT match /home capability! Got {:?}",
            result
        );

        // /home-evil should also NOT be allowed
        let result = query_path(Path::new("/home-evil"), FsAccess::Read, &caps)
            .expect("query should succeed");
        assert!(
            matches!(
                result,
                QueryResult::Denied {
                    reason: DenyReason::NotInAllowedPaths,
                    ..
                }
            ),
            "SECURITY VULNERABILITY: /home-evil should NOT match /home capability! Got {:?}",
            result
        );

        // /home itself should be allowed (exact match)
        let result =
            query_path(Path::new("/home"), FsAccess::Read, &caps).expect("query should succeed");
        assert!(
            matches!(result, QueryResult::Allowed { .. }),
            "Expected /home to be allowed with /home capability"
        );
    }

    /// SECURITY TEST: Validate HOME environment variable
    /// Per security guidelines: "Validate environment variables before use.
    /// Never assume HOME, TMPDIR, or other env vars are set or trustworthy."
    ///
    /// Note: This test modifies global environment variables, so it must run serially
    #[test]
    #[ignore] // Run with: cargo test -- --ignored --test-threads=1
    fn test_home_validation() {
        use std::env;

        let caps = CapabilitySet::default();

        // Save original HOME
        let original_home = env::var("HOME").ok();

        // Test 1: HOME not set - should fail when tilde expansion is needed
        env::remove_var("HOME");
        let result = query_path(Path::new("~/test"), FsAccess::Read, &caps);
        match &result {
            Err(NonoError::EnvVarValidation { var, reason }) => {
                assert_eq!(var, "HOME");
                assert!(
                    reason.contains("not set"),
                    "Expected 'not set' in reason, got: {}",
                    reason
                );
            }
            _ => panic!(
                "Expected HOME validation error when not set, got {:?}",
                result
            ),
        }

        // Test 2: HOME is relative path - should fail
        env::set_var("HOME", "relative/path");
        let result = query_path(Path::new("~/test"), FsAccess::Read, &caps);
        match &result {
            Err(NonoError::EnvVarValidation { var, reason }) => {
                assert_eq!(var, "HOME");
                assert!(
                    reason.contains("absolute path"),
                    "Expected 'absolute path' in reason, got: {}",
                    reason
                );
            }
            _ => panic!(
                "Expected HOME validation error for relative path, got {:?}",
                result
            ),
        }

        // Test 3: Paths without tilde should work even if HOME is invalid
        env::set_var("HOME", "invalid");
        let result = query_path(Path::new("/tmp/test"), FsAccess::Read, &caps);
        assert!(
            result.is_ok(),
            "Paths without tilde should not require valid HOME"
        );

        // Restore original HOME
        if let Some(home) = original_home {
            env::set_var("HOME", home);
        } else {
            env::remove_var("HOME");
        }
    }

    /// SECURITY REGRESSION TEST: Metadata leak prevention
    ///
    /// Verifies that query_path does NOT leak metadata about denied paths.
    /// Per security guidelines: "Metadata leaks: Even denying file content,
    /// allowing metadata reveals file existence, size, and timestamps."
    ///
    /// This test ensures that:
    /// 1. Suggestions for denied paths use directory-level flags (--read, --write, --allow)
    /// 2. The suggestion format is identical for files, directories, and non-existent paths
    /// 3. No filesystem access (path.is_file(), path.exists(), etc.) is performed on denied paths
    #[test]
    fn test_no_metadata_leak_on_denied_paths() {
        let caps = CapabilitySet::default();

        // Test 1: Sensitive path (file) - should use directory-level flag
        let result = query_path(Path::new("~/.ssh/id_rsa"), FsAccess::Read, &caps)
            .expect("query should succeed");
        match result {
            QueryResult::Denied { suggestion, .. } => {
                // Should suggest --read, NOT --read-file (which would reveal it's a file)
                assert!(
                    suggestion.starts_with("--read "),
                    "Expected --read flag for denied path, got: {}",
                    suggestion
                );
                assert!(
                    !suggestion.contains("--read-file"),
                    "METADATA LEAK: Suggestion reveals path is a file: {}",
                    suggestion
                );
            }
            _ => panic!("Expected denial for sensitive path"),
        }

        // Test 2: Non-existent path - should use same format (no metadata disclosure)
        let result = query_path(
            Path::new("/nonexistent/path/that/does/not/exist"),
            FsAccess::Write,
            &caps,
        )
        .expect("query should succeed");
        match result {
            QueryResult::Denied { suggestion, .. } => {
                // Should suggest --write (directory-level), same as if it were a real path
                assert!(
                    suggestion.starts_with("--write "),
                    "Expected --write flag for denied path, got: {}",
                    suggestion
                );
                assert!(
                    !suggestion.contains("--write-file"),
                    "METADATA LEAK: Suggestion format differs for non-existent path: {}",
                    suggestion
                );
            }
            _ => panic!("Expected denial for non-existent path"),
        }

        // Test 3: Existing directory - verify same format as files
        // Using /etc which exists on all Unix systems
        let result = query_path(Path::new("/etc"), FsAccess::ReadWrite, &caps)
            .expect("query should succeed");
        match result {
            QueryResult::Denied { suggestion, .. } => {
                // Should suggest --allow (directory-level)
                assert!(
                    suggestion.starts_with("--allow "),
                    "Expected --allow flag for denied path, got: {}",
                    suggestion
                );
                assert!(
                    !suggestion.contains("--allow-file"),
                    "Should not use file-specific flag: {}",
                    suggestion
                );
            }
            _ => panic!("Expected denial for /etc"),
        }
    }
}
