//! Feature gates loaded from `.env` at startup.
//! All dangerous capabilities default to **disabled** (false).
//! The administrator enables them explicitly via the `.env` file.

use std::env;

use crate::error::AetherError;

/// Central feature gate configuration loaded from environment variables.
/// Each gate controls a dangerous or sensitive system operation.
#[derive(Debug, Clone)]
pub struct FeatureGates {
    /// Modify Windows Boot Configuration Data (bcdedit)
    pub bcd_edit: bool,
    /// Configure HAL and crashdump/memory-dump settings
    pub hal_config: bool,
    /// Mount offline registry hives from other installations
    pub offline_registry: bool,
    /// Inject DLLs into remote processes (CreateRemoteThread)
    pub dll_inject: bool,
    /// Manipulate access tokens (impersonation, privilege enable/disable)
    pub token_manipulation: bool,
    /// Read LSA secrets (stored service account passwords)
    pub lsa_secrets: bool,
}

impl FeatureGates {
    /// Load all feature gates from environment variables.
    ///
    /// `dotenvy::dotenv()` must be called before this in `main.rs`.
    /// All gates default to `false` (disabled) when the env var is unset or != "1".
    #[must_use]
    pub fn load() -> Self {
        Self {
            bcd_edit: env_bool("AETHER_BCD_EDIT"),
            hal_config: env_bool("AETHER_HAL_CONFIG"),
            offline_registry: env_bool("AETHER_OFFLINE_REGISTRY"),
            dll_inject: env_bool("AETHER_DLL_INJECT"),
            token_manipulation: env_bool("AETHER_TOKEN_MANIPULATION"),
            lsa_secrets: env_bool("AETHER_LSA_SECRETS"),
        }
    }

    /// Verify that a specific gate is enabled, returning an `AetherError::FeatureDisabled` if not.
    ///
    /// Used inside tool handlers before executing gated operations:
    ///
    /// ```ignore
    /// self.gates.check(self.gates.dll_inject, "AETHER_DLL_INJECT")?;
    /// ```
    pub fn check(&self, enabled: bool, gate_name: &str) -> Result<(), AetherError> {
        if !enabled {
            return Err(AetherError::feature_disabled(gate_name));
        }
        Ok(())
    }
}

impl Default for FeatureGates {
    fn default() -> Self {
        Self {
            bcd_edit: false,
            hal_config: false,
            offline_registry: false,
            dll_inject: false,
            token_manipulation: false,
            lsa_secrets: false,
        }
    }
}

fn env_bool(key: &str) -> bool {
    env::var(key).unwrap_or_default().trim() == "1"
}
