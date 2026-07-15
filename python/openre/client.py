"""
OpenRE Python client for interacting with the open-re API.
"""

import os
from typing import Optional, List, Dict, Any, AsyncIterator
from dataclasses import dataclass
from datetime import datetime
import httpx
from pydantic import BaseModel, Field


@dataclass
class AuthTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"


class OpenREClient:
    """
    Client for interacting with the open-re API.
    
    Example:
        client = OpenREClient(base_url="http://localhost:8080")
        await client.login("user@example.com", "password")
        projects = await client.list_projects()
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._tokens: Optional[AuthTokens] = None
    
    async def __aenter__(self) -> "OpenREClient":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers={"Content-Type": "application/json"},
        )
        if self.api_key:
            self._client.headers["Authorization"] = f"Bearer {self.api_key}"
        elif self._tokens:
            self._client.headers["Authorization"] = f"Bearer {self._tokens.access_token}"
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self._tokens:
            headers["Authorization"] = f"Bearer {self._tokens.access_token}"
        return headers
    
    async def _request(
        self,
        method: str,
        path: str,
        **kwargs
    ) -> httpx.Response:
        if not self._client:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers=self._get_headers(),
            )
        
        url = f"{self.base_url}{path}"
        response = await self._client.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    
    # Authentication
    async def login(self, email: str, password: str, remember_me: bool = False) -> AuthTokens:
        """Login with email and password."""
        response = await self._request(
            "POST",
            "/api/auth/login",
            json={"email": email, "password": password, "remember_me": remember_me},
        )
        data = response.json()
        self._tokens = AuthTokens(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=data["expires_in"],
            token_type=data["token_type"],
        )
        if self._client:
            self._client.headers["Authorization"] = f"Bearer {self._tokens.access_token}"
        return self._tokens
    
    async def register(
        self,
        email: str,
        username: str,
        password: str,
        full_name: Optional[str] = None,
    ) -> AuthTokens:
        """Register a new user."""
        response = await self._request(
            "POST",
            "/api/auth/register",
            json={"email": email, "username": username, "password": password, "full_name": full_name},
        )
        data = response.json()
        self._tokens = AuthTokens(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=data["expires_in"],
            token_type=data["token_type"],
        )
        if self._client:
            self._client.headers["Authorization"] = f"Bearer {self._tokens.access_token}"
        return self._tokens
    
    async def refresh_token(self) -> AuthTokens:
        """Refresh the access token."""
        if not self._tokens:
            raise ValueError("No refresh token available")
        
        response = await self._request(
            "POST",
            "/api/auth/refresh",
            json={"refresh_token": self._tokens.refresh_token},
        )
        data = response.json()
        self._tokens = AuthTokens(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=data["expires_in"],
            token_type=data["token_type"],
        )
        if self._client:
            self._client.headers["Authorization"] = f"Bearer {self._tokens.access_token}"
        return self._tokens
    
    async def logout(self) -> None:
        """Logout and revoke refresh token."""
        await self._request("POST", "/api/auth/logout")
        self._tokens = None
        if self._client:
            self._client.headers.pop("Authorization", None)
    
    async def get_current_user(self) -> Dict[str, Any]:
        """Get current user info."""
        response = await self._request("GET", "/api/auth/me")
        return response.json()
    
    async def change_password(self, current_password: str, new_password: str) -> None:
        """Change password."""
        await self._request(
            "PUT",
            "/api/auth/password",
            json={"current_password": current_password, "new_password": new_password},
        )
    
    # API Keys
    async def list_api_keys(self) -> List[Dict[str, Any]]:
        """List API keys."""
        response = await self._request("GET", "/api/auth/api-keys")
        return response.json()
    
    async def create_api_key(self, name: str, scopes: List[str], expires_at: Optional[str] = None) -> Dict[str, Any]:
        """Create an API key."""
        response = await self._request(
            "POST",
            "/api/auth/api-keys",
            json={"name": name, "scopes": scopes, "expires_at": expires_at},
        )
        return response.json()
    
    async def revoke_api_key(self, key_id: str) -> None:
        """Revoke an API key."""
        await self._request("DELETE", f"/api/auth/api-keys/{key_id}")
    
    # Projects
    async def list_projects(
        self,
        page: int = 1,
        per_page: int = 20,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List projects."""
        params = {"page": page, "per_page": per_page}
        if search:
            params["search"] = search
        response = await self._request("GET", "/api/projects", params=params)
        return response.json()
    
    async def create_project(
        self,
        name: str,
        description: Optional[str] = None,
        is_public: bool = False,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a project."""
        response = await self._request(
            "POST",
            "/api/projects",
            json={"name": name, "description": description, "is_public": is_public, "settings": settings},
        )
        return response.json()
    
    async def get_project(self, project_id: str) -> Dict[str, Any]:
        """Get project details."""
        response = await self._request("GET", f"/api/projects/{project_id}")
        return response.json()
    
    async def update_project(
        self,
        project_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        is_public: Optional[bool] = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a project."""
        data = {}
        if name is not None:
            data["name"] = name
        if description is not None:
            data["description"] = description
        if is_public is not None:
            data["is_public"] = is_public
        if settings is not None:
            data["settings"] = settings
        
        response = await self._request("PUT", f"/api/projects/{project_id}", json=data)
        return response.json()
    
    async def delete_project(self, project_id: str) -> None:
        """Delete a project."""
        await self._request("DELETE", f"/api/projects/{project_id}")
    
    # Files
    async def list_files(
        self,
        page: int = 1,
        per_page: int = 20,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List files."""
        params = {"page": page, "per_page": per_page}
        if project_id:
            params["project_id"] = project_id
        if status:
            params["status"] = status
        response = await self._request("GET", "/api/files", params=params)
        return response.json()
    
    async def upload_file(
        self,
        file_path: str,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Upload a file."""
        import aiofiles
        
        async with aiofiles.open(file_path, "rb") as f:
            content = await f.read()
        
        filename = os.path.basename(file_path)
        files = {"file": (filename, content, "application/octet-stream")}
        data = {}
        if project_id:
            data["project_id"] = project_id
        
        response = await self._client.post(
            "/api/files",
            files=files,
            data=data,
        )
        response.raise_for_status()
        return response.json()
    
    async def get_file(self, file_id: str) -> Dict[str, Any]:
        """Get file details."""
        response = await self._request("GET", f"/api/files/{file_id}")
        return response.json()
    
    async def delete_file(self, file_id: str) -> None:
        """Delete a file."""
        await self._request("DELETE", f"/api/files/{file_id}")
    
    async def download_file(self, file_id: str) -> bytes:
        """Download a file."""
        response = await self._client.get(f"/api/files/{file_id}/download")
        response.raise_for_status()
        return response.content
    
    # Analysis
    async def start_analysis(
        self,
        file_id: str,
        stages: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        priority: str = "default",
    ) -> Dict[str, Any]:
        """Start analysis on a file."""
        response = await self._request(
            "POST",
            "/api/analysis",
            json={"file_id": file_id, "stages": stages, "config": config, "priority": priority},
        )
        return response.json()
    
    async def get_analysis_status(self, job_id: str) -> Dict[str, Any]:
        """Get analysis status."""
        response = await self._request("GET", f"/api/analysis/{job_id}")
        return response.json()
    
    async def get_analysis_results(self, job_id: str) -> Dict[str, Any]:
        """Get analysis results."""
        response = await self._request("GET", f"/api/analysis/{job_id}/results")
        return response.json()
    
    async def cancel_analysis(self, job_id: str) -> Dict[str, Any]:
        """Cancel analysis."""
        response = await self._request("POST", f"/api/analysis/{job_id}/cancel")
        return response.json()
    
    async def retry_analysis(self, job_id: str) -> Dict[str, Any]:
        """Retry analysis."""
        response = await self._request("POST", f"/api/analysis/{job_id}/retry")
        return response.json()
    
    async def list_analyses(
        self,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List analyses."""
        params = {"page": page, "per_page": per_page}
        if status:
            params["status"] = status
        response = await self._request("GET", "/api/analysis", params=params)
        return response.json()
    
    # Functions
    async def list_functions(
        self,
        page: int = 1,
        per_page: int = 50,
        project_id: Optional[str] = None,
        file_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List functions."""
        params = {"page": page, "per_page": per_page}
        if project_id:
            params["project_id"] = project_id
        if file_id:
            params["file_id"] = file_id
        if name:
            params["name"] = name
        response = await self._request("GET", "/api/functions", params=params)
        return response.json()
    
    async def get_function(self, function_id: str) -> Dict[str, Any]:
        """Get function details."""
        response = await self._request("GET", f"/api/functions/{function_id}")
        return response.json()
    
    async def get_pseudocode(self, function_id: str) -> Dict[str, Any]:
        """Get function pseudocode."""
        response = await self._request("GET", f"/api/functions/{function_id}/pseudocode")
        return response.json()
    
    async def get_cfg(self, function_id: str) -> Dict[str, Any]:
        """Get function CFG."""
        response = await self._request("GET", f"/api/functions/{function_id}/cfg")
        return response.json()
    
    async def get_xrefs(
        self,
        function_id: str,
        direction: str = "both",
    ) -> Dict[str, Any]:
        """Get function cross-references."""
        response = await self._request(
            "GET",
            f"/api/functions/{function_id}/xrefs",
            params={"direction": direction},
        )
        return response.json()
    
    async def get_annotations(self, function_id: str) -> Dict[str, Any]:
        """Get function annotations."""
        response = await self._request("GET", f"/api/functions/{function_id}/annotations")
        return response.json()
    
    # AI
    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """Chat completion."""
        response = await self._request(
            "POST",
            "/api/ai/chat",
            json={
                "messages": messages,
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": stream,
            },
        )
        return response.json()
    
    async def analyze_function(
        self,
        function_id: str,
        project_id: str,
    ) -> Dict[str, Any]:
        """Analyze function with AI."""
        response = await self._request(
            "POST",
            "/api/ai/analyze",
            json={"function_id": function_id, "project_id": project_id},
        )
        return response.json()
    
    async def list_templates(self) -> List[Dict[str, Any]]:
        """List prompt templates."""
        response = await self._request("GET", "/api/ai/templates")
        return response.json()
    
    # Plugins
    async def list_plugins(
        self,
        page: int = 1,
        per_page: int = 20,
        plugin_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """List plugins."""
        params = {"page": page, "per_page": per_page}
        if plugin_type:
            params["plugin_type"] = plugin_type
        if enabled is not None:
            params["enabled"] = enabled
        response = await self._request("GET", "/api/plugins", params=params)
        return response.json()
    
    async def get_plugin(self, plugin_id: str) -> Dict[str, Any]:
        """Get plugin details."""
        response = await self._request("GET", f"/api/plugins/{plugin_id}")
        return response.json()
    
    async def install_plugin(
        self,
        source: Dict[str, Any],
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Install a plugin."""
        data = {"source": source}
        if version:
            data["version"] = version
        response = await self._request("POST", "/api/plugins", json=data)
        return response.json()
    
    async def uninstall_plugin(self, plugin_id: str) -> None:
        """Uninstall a plugin."""
        await self._request("DELETE", f"/api/plugins/{plugin_id}")
    
    async def enable_plugin(self, plugin_id: str) -> Dict[str, Any]:
        """Enable a plugin."""
        response = await self._request("POST", f"/api/plugins/{plugin_id}/enable")
        return response.json()
    
    async def disable_plugin(self, plugin_id: str) -> Dict[str, Any]:
        """Disable a plugin."""
        response = await self._request("POST", f"/api/plugins/{plugin_id}/disable")
        return response.json()
    
    async def configure_plugin(self, plugin_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure a plugin."""
        response = await self._request("PUT", f"/api/plugins/{plugin_id}/configure", json={"config": config})
        return response.json()