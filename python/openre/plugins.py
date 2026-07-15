"""
Plugin manager for open-re Python bindings.
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from .client import OpenREClient
from .models import Plugin


@dataclass
class PluginSource:
    """Plugin installation source."""
    type: str  # "registry", "local", "git"
    name: Optional[str] = None
    path: Optional[str] = None
    url: Optional[str] = None
    rev: Optional[str] = None
    
    @classmethod
    def from_registry(cls, name: str) -> "PluginSource":
        return cls(type="registry", name=name)
    
    @classmethod
    def from_local(cls, path: str) -> "PluginSource":
        return cls(type="local", path=path)
    
    @classmethod
    def from_git(cls, url: str, rev: Optional[str] = None) -> "PluginSource":
        return cls(type="git", url=url, rev=rev)
    
    def to_dict(self) -> Dict[str, Any]:
        data = {"type": self.type}
        if self.name:
            data["name"] = self.name
        if self.path:
            data["path"] = self.path
        if self.url:
            data["url"] = self.url
        if self.rev:
            data["rev"] = self.rev
        return data


class PluginManager:
    """
    High-level manager for plugin operations.
    
    Example:
        async with OpenREClient() as client:
            await client.login("user@example.com", "password")
            manager = PluginManager(client)
            plugin = await manager.install(PluginSource.from_registry("ghidra-loader"))
    """
    
    def __init__(self, client: OpenREClient):
        self.client = client
    
    async def list(
        self,
        page: int = 1,
        per_page: int = 20,
        plugin_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """List plugins."""
        return await self.client.list_plugins(page, per_page, plugin_type, enabled)
    
    async def get(self, plugin_id: str) -> Plugin:
        """Get plugin details."""
        response = await self.client.get_plugin(plugin_id)
        return Plugin(**response)
    
    async def install(
        self,
        source: PluginSource,
        version: Optional[str] = None,
    ) -> Plugin:
        """Install a plugin."""
        response = await self.client.install_plugin(source.to_dict(), version)
        return Plugin(**response)
    
    async def uninstall(self, plugin_id: str) -> None:
        """Uninstall a plugin."""
        await self.client.uninstall_plugin(plugin_id)
    
    async def enable(self, plugin_id: str) -> Plugin:
        """Enable a plugin."""
        response = await self.client.enable_plugin(plugin_id)
        return Plugin(**response)
    
    async def disable(self, plugin_id: str) -> Plugin:
        """Disable a plugin."""
        response = await self.client.disable_plugin(plugin_id)
        return Plugin(**response)
    
    async def configure(self, plugin_id: str, config: Dict[str, Any]) -> Plugin:
        """Configure a plugin."""
        response = await self.client.configure_plugin(plugin_id, config)
        return Plugin(**response)
    
    async def get_enabled_plugins(self) -> List[Plugin]:
        """Get all enabled plugins."""
        response = await self.list(enabled=True, per_page=100)
        return [Plugin(**p) for p in response.get("plugins", [])]
    
    async def get_plugins_by_type(self, plugin_type: str) -> List[Plugin]:
        """Get plugins by type."""
        response = await self.list(plugin_type=plugin_type, per_page=100)
        return [Plugin(**p) for p in response.get("plugins", [])]