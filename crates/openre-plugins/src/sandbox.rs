//! Plugin sandboxing for open-re

use openre_core::error::Result;
use openre_core::ids::Capability;
use std::path::PathBuf;
use std::collections::HashMap;

/// Sandbox configuration
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_stack_kb: usize,
    pub allowed_host_functions: Vec<String>,
    pub filesystem: FilesystemPermission,
    pub network: NetworkPermission,
}

#[derive(Debug, Clone)]
pub enum FilesystemPermission {
    None,
    Read { paths: Vec<PathBuf> },
    Write { paths: Vec<PathBuf> },
    Sandbox { mount_points: Vec<MountPoint> },
}

#[derive(Debug, Clone)]
pub struct MountPoint {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
    pub readonly: bool,
}

#[derive(Debug, Clone)]
pub enum NetworkPermission {
    None,
    Localhost { ports: Vec<u16> },
    Egress { domains: Vec<String> },
}

/// Sandbox for plugin execution
pub struct PluginSandbox {
    config: SandboxConfig,
    capability_enforcer: CapabilityEnforcer,
}

impl PluginSandbox {
    pub fn new(config: SandboxConfig) -> Self {
        let granted_capabilities = Self::permissions_to_capabilities(&config.filesystem, &config.network);
        let capability_enforcer = CapabilityEnforcer::new(granted_capabilities);
        
        Self {
            config,
            capability_enforcer,
        }
    }

    fn permissions_to_capabilities(
        fs: &FilesystemPermission,
        net: &NetworkPermission,
    ) -> Vec<Capability> {
        let mut caps = Vec::new();
        
        match fs {
            FilesystemPermission::Read { .. } => caps.push(Capability::ReadBinary),
            FilesystemPermission::Write { .. } => {
                caps.push(Capability::ReadBinary);
                caps.push(Capability::WriteBinary);
            }
            FilesystemPermission::Sandbox { .. } => {
                caps.push(Capability::ReadBinary);
            }
            FilesystemPermission::None => {}
        }
        
        match net {
            NetworkPermission::Localhost { .. } | NetworkPermission::Egress { .. } => {
                caps.push(Capability::NetworkAccess);
            }
            NetworkPermission::None => {}
        }
        
        caps
    }

    pub fn check_filesystem_read(&self, path: &PathBuf) -> Result<()> {
        match &self.config.filesystem {
            FilesystemPermission::None => Err(openre_core::Error::Forbidden("Filesystem access denied".into())),
            FilesystemPermission::Read { paths } => {
                if paths.iter().any(|p| path.starts_with(p)) {
                    Ok(())
                } else {
                    Err(openre_core::Error::Forbidden(format!("Path not allowed: {}", path.display())))
                }
            }
            FilesystemPermission::Write { paths } => {
                if paths.iter().any(|p| path.starts_with(p)) {
                    Ok(())
                } else {
                    Err(openre_core::Error::Forbidden(format!("Path not allowed: {}", path.display())))
                }
            }
            FilesystemPermission::Sandbox { mount_points } => {
                if mount_points.iter().any(|m| path.starts_with(&m.guest_path)) {
                    Ok(())
                } else {
                    Err(openre_core::Error::Forbidden(format!("Path not allowed: {}", path.display())))
                }
            }
        }
    }

    pub fn check_filesystem_write(&self, path: &PathBuf) -> Result<()> {
        match &self.config.filesystem {
            FilesystemPermission::Write { paths } => {
                if paths.iter().any(|p| path.starts_with(p)) {
                    Ok(())
                } else {
                    Err(openre_core::Error::Forbidden(format!("Path not allowed for write: {}", path.display())))
                }
            }
            FilesystemPermission::Sandbox { mount_points } => {
                if mount_points.iter().any(|m| path.starts_with(&m.guest_path) && !m.readonly) {
                    Ok(())
                } else {
                    Err(openre_core::Error::Forbidden(format!("Path not allowed for write: {}", path.display())))
                }
            }
            _ => Err(openre_core::Error::Forbidden("Write access denied".into())),
        }
    }

    pub fn check_network(&self, host: &str, port: u16) -> Result<()> {
        match &self.config.network {
            NetworkPermission::None => Err(openre_core::Error::Forbidden("Network access denied".into())),
            NetworkPermission::Localhost { ports } => {
                if (host == "localhost" || host == "127.0.0.1") && ports.contains(&port) {
                    Ok(())
                } else {
                    Err(openre_core::Error::Forbidden(format!("Network access denied: {}:{}", host, port)))
                }
            }
            NetworkPermission::Egress { domains } => {
                if domains.iter().any(|d| host.ends_with(d)) {
                    Ok(())
                } else {
                    Err(openre_core::Error::Forbidden(format!("Domain not allowed: {}", host)))
                }
            }
        }
    }

    pub fn capability_enforcer(&self) -> &CapabilityEnforcer {
        &self.capability_enforcer
    }
}

/// Capability enforcer for runtime permission checking
pub struct CapabilityEnforcer {
    granted: std::collections::HashSet<Capability>,
}

impl CapabilityEnforcer {
    pub fn new(granted: Vec<Capability>) -> Self {
        Self {
            granted: granted.into_iter().collect(),
        }
    }

    pub fn check(&self, capability: Capability) -> Result<()> {
        if self.granted.contains(&capability) {
            Ok(())
        } else {
            Err(openre_core::Error::Forbidden(format!("Capability not granted: {:?}", capability)))
        }
    }

    pub fn has(&self, capability: Capability) -> bool {
        self.granted.contains(&capability)
    }
}