"""
OpenRE Python client for interacting with the open-re API.

This client provides access to all open-re functionality including:
- Project and file management
- Binary analysis operations
- AI-powered code analysis
- Plugin management
- AI Security Analyst features (explain, remediate, correlate, prioritize, summarize, query, compare)
- Evidence-Grounded LLM Service (Phase 8)
"""

import os
from typing import Optional, List, Dict, Any, AsyncIterator, Union
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


# ==================== Grounded LLM Service Models (Phase 8) ====================

class GroundedEvidenceReference(BaseModel):
    """Evidence reference with ID for grounding validation."""
    evidence_id: str
    evidence_type: str
    description: str
    content_preview: str


class GroundedAttackScenario(BaseModel):
    """Attack scenario with evidence grounding."""
    description: str
    supporting_evidence: List[str]
    likelihood: str  # Certain, Likely, Possible, Unlikely, Speculative


class ExplanationConfidence(BaseModel):
    """Confidence level for explanations."""
    level: str  # High, Medium, Low, Uncertain
    reason: Optional[str] = None


class LlmExplanation(BaseModel):
    """LLM Explanation grounded in evidence."""
    finding_id: str
    root_cause: str
    security_impact: str
    attack_scenarios: List[GroundedAttackScenario]
    confidence: ExplanationConfidence
    false_positive_considerations: List[str]
    evidence_references: List[GroundedEvidenceReference]
    model_info: Dict[str, Any]


class CorrelationType(str):
    SharedRootCause = "SharedRootCause"
    AttackChain = "AttackChain"
    SharedTechnology = "SharedTechnology"
    SharedAttackVector = "SharedAttackVector"
    SharedConfiguration = "SharedConfiguration"


class GroundedCorrelationGroup(BaseModel):
    """A group of correlated findings sharing evidence."""
    finding_ids: List[str]
    correlation_type: str
    relationship: str
    shared_evidence_ids: List[str]
    combined_risk: str
    mitigation_approach: str


class LlmCorrelation(BaseModel):
    """LLM Correlation grounded in shared evidence."""
    scan_id: str
    correlations: List[GroundedCorrelationGroup]
    risk_assessment: str
    evidence_references: List[GroundedEvidenceReference]
    model_info: Dict[str, Any]


class GroundedRemediationStep(BaseModel):
    """Remediation step with evidence grounding."""
    step_number: int
    description: str
    rationale: str
    supporting_evidence: List[str]
    technology_notes: Optional[str] = None


class GroundedCodeExample(BaseModel):
    """Code example with evidence grounding."""
    language: str
    vulnerable: str
    fixed: str
    explanation: str
    vulnerability_evidence: List[str]


class GroundedVerificationStep(BaseModel):
    """Verification step with evidence grounding."""
    description: str
    expected_result: str
    confirmation_evidence: List[str]


class TechnologyGuidance(BaseModel):
    """Technology-specific remediation guidance."""
    technology: str
    version: Optional[str] = None
    config_changes: List[str]
    framework_mitigation: Optional[str] = None
    related_evidence: List[str]


class RemediationEffort(str):
    Trivial = "Trivial"
    Low = "Low"
    Medium = "Medium"
    High = "High"
    VeryHigh = "VeryHigh"


class RemediationPriority(str):
    Immediate = "Immediate"
    High = "High"
    Medium = "Medium"
    Low = "Low"
    Deferred = "Deferred"


class LlmRemediation(BaseModel):
    """LLM Remediation grounded in evidence + technology context."""
    finding_id: str
    summary: str
    steps: List[GroundedRemediationStep]
    code_examples: List[GroundedCodeExample]
    verification_steps: List[GroundedVerificationStep]
    effort: str
    priority: str
    technology_guidance: List[TechnologyGuidance]
    evidence_references: List[GroundedEvidenceReference]
    model_info: Dict[str, Any]


class GroundedClaim(BaseModel):
    """A claim with evidence grounding."""
    claim: str
    evidence_ids: List[str]
    confidence: float


class UngroundedClaim(BaseModel):
    """A claim lacking evidence grounding."""
    claim: str
    reason: str
    suggested_evidence: List[str]


class GroundingValidationResult(BaseModel):
    """Result of grounding validation."""
    fully_grounded: bool
    grounded_claims: List[GroundedClaim]
    ungrounded_claims: List[UngroundedClaim]
    referenced_evidence_ids: List[str]
    unused_evidence_ids: List[str]


class Audience(str):
    Developer = "Developer"
    SecurityEngineer = "SecurityEngineer"
    Manager = "Manager"
    Executive = "Executive"


class SummaryFinding(BaseModel):
    """Simplified finding for summaries."""
    finding_id: str
    title: str
    severity: str
    brief: str
    priority: str


class ExecutiveSummary(BaseModel):
    """Executive summary for different audiences."""
    scan_id: str
    audience: str
    key_findings: List[SummaryFinding]
    risk_assessment: str
    recommended_actions: List[str]
    business_impact: Optional[str] = None
    technical_details: Optional[List[str]] = None
    evidence_references: List[GroundedEvidenceReference]
    model_info: Dict[str, Any]


class RiskChange(BaseModel):
    """Risk change for comparison."""
    finding_id: str
    description: str
    previous_risk: int
    current_risk: int


class ScanComparison(BaseModel):
    """Scan comparison result."""
    base_scan_id: str
    target_scan_id: str
    new_findings: List[str]
    fixed_findings: List[str]
    increased_risk: List[RiskChange]
    decreased_risk: List[RiskChange]
    summary: str
    security_posture_assessment: str
    evidence_references: List[GroundedEvidenceReference]
    model_info: Dict[str, Any]


class ModelInfo(BaseModel):
    """Model information for reproducibility."""
    model: str
    version: Optional[str] = None
    timestamp: datetime


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

    # AI Security Analyst
    async def explain_finding(
        self,
        scan_id: str,
        finding_id: str,
    ) -> Dict[str, Any]:
        """Explain a security finding."""
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"scan_id": scan_id, "finding_id": finding_id},
        )
        return response.json()

    async def stream_explain_finding(
        self,
        scan_id: str,
        finding_id: str,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"scan_id": scan_id, "finding_id": finding_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Phase 8: Evidence-Grounded LLM Service ====================

    async def explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> LlmExplanation:
        """
        Explain a security finding with evidence grounding.

        Args:
            finding_id: The ID of the finding to explain
            require_evidence: If True, validates that all claims reference evidence IDs

        Returns:
            LlmExplanation with grounded root cause, impact, attack scenarios, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If require_evidence=True and response has ungrounded claims
        """
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"finding_id": finding_id, "require_evidence": require_evidence},
        )
        data = response.json()

        explanation = LlmExplanation(**data)

        # Validate evidence grounding if required
        if require_evidence:
            self._validate_explanation_grounding(explanation)

        return explanation

    async def stream_explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"finding_id": finding_id, "require_evidence": str(require_evidence).lower()}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> LlmCorrelation:
        """
        Correlate findings based on shared evidence.

        Args:
            finding_ids: List of finding IDs to correlate
            min_confidence: Minimum confidence threshold for correlations (0.0-1.0)

        Returns:
            LlmCorrelation with grouped findings sharing evidence, risk assessment, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If correlations reference non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"finding_ids": finding_ids, "min_confidence": min_confidence},
        )
        data = response.json()

        correlation = LlmCorrelation(**data)

        # Validate evidence grounding
        self._validate_correlation_grounding(correlation)

        return correlation

    async def stream_correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"finding_ids": json.dumps(finding_ids), "min_confidence": str(min_confidence)}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> LlmRemediation:
        """
        Generate remediation plan grounded in finding evidence + technology context.

        Args:
            finding_id: The ID of the finding to remediate
            context: Optional additional context (technology stack, compliance requirements, etc.)

        Returns:
            LlmRemediation with steps, code examples, verification steps, technology guidance, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If remediation references non-existent evidence IDs
        """
        payload = {"finding_id": finding_id}
        if context:
            payload["context"] = context

        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json=payload,
        )
        data = response.json()

        remediation = LlmRemediation(**data)

        # Validate evidence grounding
        self._validate_remediation_grounding(remediation)

        return remediation

    async def stream_suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"finding_id": finding_id}
            if context:
                params["context"] = json.dumps(context)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> ExecutiveSummary:
        """
        Generate executive summary with evidence grounding.

        Args:
            scan_id: The ID of the scan to summarize
            max_findings: Maximum number of findings to include (default: 10)
            audience: Target audience - "developer", "security_engineer", "manager", "executive" (default: "executive")

        Returns:
            ExecutiveSummary with key findings, risk assessment, recommended actions, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If summary references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "max_findings": max_findings, "audience": audience},
        )
        data = response.json()

        summary = ExecutiveSummary(**data)

        # Validate evidence grounding
        self._validate_summary_grounding(summary)

        return summary

    async def stream_executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "max_findings": str(max_findings), "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> ScanComparison:
        """
        Compare two scans for changes with evidence grounding.

        Args:
            baseline_id: The ID of the baseline scan
            current_id: The ID of the current scan to compare against baseline

        Returns:
            ScanComparison with new/fixed findings, risk changes, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If comparison references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"baseline_id": baseline_id, "current_id": current_id},
        )
        data = response.json()

        comparison = ScanComparison(**data)

        # Validate evidence grounding
        self._validate_comparison_grounding(comparison)

        return comparison

    async def stream_compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"baseline_id": baseline_id, "current_id": current_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Grounding Validation Helpers ====================

    def _validate_explanation_grounding(self, explanation: LlmExplanation) -> None:
        """Validate that explanation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in explanation.evidence_references}

        # Check root_cause and security_impact have evidence references
        for field_name, field_value in [
            ("root_cause", explanation.root_cause),
            ("security_impact", explanation.security_impact),
        ]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Explanation {field_name} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check attack scenarios
        for scenario in explanation.attack_scenarios:
            for eid in scenario.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Attack scenario references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_correlation_grounding(self, correlation: LlmCorrelation) -> None:
        """Validate that correlation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in correlation.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(correlation.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Correlation risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check each correlation group
        for group in correlation.correlations:
            for eid in group.shared_evidence_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Correlation group references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            # Check relationship and combined_risk
            for field_value in [group.relationship, group.combined_risk, group.mitigation_approach]:
                referenced_ids = self._extract_evidence_ids(field_value)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Correlation group field references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_remediation_grounding(self, remediation: LlmRemediation) -> None:
        """Validate that remediation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in remediation.evidence_references}

        # Check summary
        referenced_ids = self._extract_evidence_ids(remediation.summary)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Remediation summary references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check steps
        for step in remediation.steps:
            for eid in step.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Remediation step {step.step_number} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if step.rationale:
                referenced_ids = self._extract_evidence_ids(step.rationale)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Remediation step {step.step_number} rationale references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check code examples
        for example in remediation.code_examples:
            for eid in example.vulnerability_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Code example references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if example.explanation:
                referenced_ids = self._extract_evidence_ids(example.explanation)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Code example explanation references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check verification steps
        for vstep in remediation.verification_steps:
            for eid in vstep.confirmation_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Verification step references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technology guidance
        for tech in remediation.technology_guidance:
            for eid in tech.related_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Technology guidance for {tech.technology} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_summary_grounding(self, summary: ExecutiveSummary) -> None:
        """Validate that executive summary claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in summary.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(summary.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Summary risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check recommended_actions
        for action in summary.recommended_actions:
            referenced_ids = self._extract_evidence_ids(action)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Recommended action references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check business_impact
        if summary.business_impact:
            referenced_ids = self._extract_evidence_ids(summary.business_impact)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Business impact references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technical_details
        if summary.technical_details:
            for detail in summary.technical_details:
                referenced_ids = self._extract_evidence_ids(detail)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Technical detail references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_comparison_grounding(self, comparison: ScanComparison) -> None:
        """Validate that scan comparison claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in comparison.evidence_references}

        # Check summary and security_posture_assessment
        for field_value in [comparison.summary, comparison.security_posture_assessment]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Comparison field references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check increased_risk
        for risk in comparison.increased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Increased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check decreased_risk
        for risk in comparison.decreased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Decreased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract evidence IDs from text in [Evidence: <id>] format."""
        import re
        pattern = r"\[Evidence:\s*([^\]]+)\]"
        matches = re.findall(pattern, text)
        return [match.strip() for match in matches]

    async def generate_remediation(
        self,
        scan_id: str,
        finding_id: str,
    ) -> Dict[str, Any]:
        """Generate remediation plan for a security finding."""
        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json={"scan_id": scan_id, "finding_id": finding_id},
        )
        return response.json()

    async def stream_generate_remediation(
        self,
        scan_id: str,
        finding_id: str,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan for a security finding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"scan_id": scan_id, "finding_id": finding_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Phase 8: Evidence-Grounded LLM Service ====================

    async def explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> LlmExplanation:
        """
        Explain a security finding with evidence grounding.

        Args:
            finding_id: The ID of the finding to explain
            require_evidence: If True, validates that all claims reference evidence IDs

        Returns:
            LlmExplanation with grounded root cause, impact, attack scenarios, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If require_evidence=True and response has ungrounded claims
        """
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"finding_id": finding_id, "require_evidence": require_evidence},
        )
        data = response.json()

        explanation = LlmExplanation(**data)

        # Validate evidence grounding if required
        if require_evidence:
            self._validate_explanation_grounding(explanation)

        return explanation

    async def stream_explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"finding_id": finding_id, "require_evidence": str(require_evidence).lower()}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> LlmCorrelation:
        """
        Correlate findings based on shared evidence.

        Args:
            finding_ids: List of finding IDs to correlate
            min_confidence: Minimum confidence threshold for correlations (0.0-1.0)

        Returns:
            LlmCorrelation with grouped findings sharing evidence, risk assessment, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If correlations reference non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"finding_ids": finding_ids, "min_confidence": min_confidence},
        )
        data = response.json()

        correlation = LlmCorrelation(**data)

        # Validate evidence grounding
        self._validate_correlation_grounding(correlation)

        return correlation

    async def stream_correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"finding_ids": json.dumps(finding_ids), "min_confidence": str(min_confidence)}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> LlmRemediation:
        """
        Generate remediation plan grounded in finding evidence + technology context.

        Args:
            finding_id: The ID of the finding to remediate
            context: Optional additional context (technology stack, compliance requirements, etc.)

        Returns:
            LlmRemediation with steps, code examples, verification steps, technology guidance, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If remediation references non-existent evidence IDs
        """
        payload = {"finding_id": finding_id}
        if context:
            payload["context"] = context

        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json=payload,
        )
        data = response.json()

        remediation = LlmRemediation(**data)

        # Validate evidence grounding
        self._validate_remediation_grounding(remediation)

        return remediation

    async def stream_suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"finding_id": finding_id}
            if context:
                params["context"] = json.dumps(context)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> ExecutiveSummary:
        """
        Generate executive summary with evidence grounding.

        Args:
            scan_id: The ID of the scan to summarize
            max_findings: Maximum number of findings to include (default: 10)
            audience: Target audience - "developer", "security_engineer", "manager", "executive" (default: "executive")

        Returns:
            ExecutiveSummary with key findings, risk assessment, recommended actions, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If summary references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "max_findings": max_findings, "audience": audience},
        )
        data = response.json()

        summary = ExecutiveSummary(**data)

        # Validate evidence grounding
        self._validate_summary_grounding(summary)

        return summary

    async def stream_executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "max_findings": str(max_findings), "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> ScanComparison:
        """
        Compare two scans for changes with evidence grounding.

        Args:
            baseline_id: The ID of the baseline scan
            current_id: The ID of the current scan to compare against baseline

        Returns:
            ScanComparison with new/fixed findings, risk changes, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If comparison references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"baseline_id": baseline_id, "current_id": current_id},
        )
        data = response.json()

        comparison = ScanComparison(**data)

        # Validate evidence grounding
        self._validate_comparison_grounding(comparison)

        return comparison

    async def stream_compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"baseline_id": baseline_id, "current_id": current_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Grounding Validation Helpers ====================

    def _validate_explanation_grounding(self, explanation: LlmExplanation) -> None:
        """Validate that explanation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in explanation.evidence_references}

        # Check root_cause and security_impact have evidence references
        for field_name, field_value in [
            ("root_cause", explanation.root_cause),
            ("security_impact", explanation.security_impact),
        ]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Explanation {field_name} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check attack scenarios
        for scenario in explanation.attack_scenarios:
            for eid in scenario.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Attack scenario references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_correlation_grounding(self, correlation: LlmCorrelation) -> None:
        """Validate that correlation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in correlation.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(correlation.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Correlation risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check each correlation group
        for group in correlation.correlations:
            for eid in group.shared_evidence_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Correlation group references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            # Check relationship and combined_risk
            for field_value in [group.relationship, group.combined_risk, group.mitigation_approach]:
                referenced_ids = self._extract_evidence_ids(field_value)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Correlation group field references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_remediation_grounding(self, remediation: LlmRemediation) -> None:
        """Validate that remediation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in remediation.evidence_references}

        # Check summary
        referenced_ids = self._extract_evidence_ids(remediation.summary)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Remediation summary references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check steps
        for step in remediation.steps:
            for eid in step.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Remediation step {step.step_number} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if step.rationale:
                referenced_ids = self._extract_evidence_ids(step.rationale)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Remediation step {step.step_number} rationale references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check code examples
        for example in remediation.code_examples:
            for eid in example.vulnerability_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Code example references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if example.explanation:
                referenced_ids = self._extract_evidence_ids(example.explanation)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Code example explanation references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check verification steps
        for vstep in remediation.verification_steps:
            for eid in vstep.confirmation_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Verification step references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technology guidance
        for tech in remediation.technology_guidance:
            for eid in tech.related_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Technology guidance for {tech.technology} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_summary_grounding(self, summary: ExecutiveSummary) -> None:
        """Validate that executive summary claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in summary.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(summary.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Summary risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check recommended_actions
        for action in summary.recommended_actions:
            referenced_ids = self._extract_evidence_ids(action)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Recommended action references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check business_impact
        if summary.business_impact:
            referenced_ids = self._extract_evidence_ids(summary.business_impact)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Business impact references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technical_details
        if summary.technical_details:
            for detail in summary.technical_details:
                referenced_ids = self._extract_evidence_ids(detail)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Technical detail references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_comparison_grounding(self, comparison: ScanComparison) -> None:
        """Validate that scan comparison claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in comparison.evidence_references}

        # Check summary and security_posture_assessment
        for field_value in [comparison.summary, comparison.security_posture_assessment]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Comparison field references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check increased_risk
        for risk in comparison.increased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Increased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check decreased_risk
        for risk in comparison.decreased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Decreased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract evidence IDs from text in [Evidence: <id>] format."""
        import re
        pattern = r"\[Evidence:\s*([^\]]+)\]"
        matches = re.findall(pattern, text)
        return [match.strip() for match in matches]

    async def correlate_findings(
        self,
        scan_id: str,
        filter: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Correlate findings to identify relationships."""
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"scan_id": scan_id, "filter": filter},
        )
        return response.json()

    async def stream_correlate_findings(
        self,
        scan_id: str,
        filter: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings to identify relationships."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"scan_id": scan_id}
            if filter:
                params["filter"] = json.dumps(filter)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Phase 8: Evidence-Grounded LLM Service ====================

    async def explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> LlmExplanation:
        """
        Explain a security finding with evidence grounding.

        Args:
            finding_id: The ID of the finding to explain
            require_evidence: If True, validates that all claims reference evidence IDs

        Returns:
            LlmExplanation with grounded root cause, impact, attack scenarios, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If require_evidence=True and response has ungrounded claims
        """
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"finding_id": finding_id, "require_evidence": require_evidence},
        )
        data = response.json()

        explanation = LlmExplanation(**data)

        # Validate evidence grounding if required
        if require_evidence:
            self._validate_explanation_grounding(explanation)

        return explanation

    async def stream_explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"finding_id": finding_id, "require_evidence": str(require_evidence).lower()}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> LlmCorrelation:
        """
        Correlate findings based on shared evidence.

        Args:
            finding_ids: List of finding IDs to correlate
            min_confidence: Minimum confidence threshold for correlations (0.0-1.0)

        Returns:
            LlmCorrelation with grouped findings sharing evidence, risk assessment, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If correlations reference non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"finding_ids": finding_ids, "min_confidence": min_confidence},
        )
        data = response.json()

        correlation = LlmCorrelation(**data)

        # Validate evidence grounding
        self._validate_correlation_grounding(correlation)

        return correlation

    async def stream_correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"finding_ids": json.dumps(finding_ids), "min_confidence": str(min_confidence)}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> LlmRemediation:
        """
        Generate remediation plan grounded in finding evidence + technology context.

        Args:
            finding_id: The ID of the finding to remediate
            context: Optional additional context (technology stack, compliance requirements, etc.)

        Returns:
            LlmRemediation with steps, code examples, verification steps, technology guidance, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If remediation references non-existent evidence IDs
        """
        payload = {"finding_id": finding_id}
        if context:
            payload["context"] = context

        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json=payload,
        )
        data = response.json()

        remediation = LlmRemediation(**data)

        # Validate evidence grounding
        self._validate_remediation_grounding(remediation)

        return remediation

    async def stream_suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"finding_id": finding_id}
            if context:
                params["context"] = json.dumps(context)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> ExecutiveSummary:
        """
        Generate executive summary with evidence grounding.

        Args:
            scan_id: The ID of the scan to summarize
            max_findings: Maximum number of findings to include (default: 10)
            audience: Target audience - "developer", "security_engineer", "manager", "executive" (default: "executive")

        Returns:
            ExecutiveSummary with key findings, risk assessment, recommended actions, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If summary references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "max_findings": max_findings, "audience": audience},
        )
        data = response.json()

        summary = ExecutiveSummary(**data)

        # Validate evidence grounding
        self._validate_summary_grounding(summary)

        return summary

    async def stream_executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "max_findings": str(max_findings), "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> ScanComparison:
        """
        Compare two scans for changes with evidence grounding.

        Args:
            baseline_id: The ID of the baseline scan
            current_id: The ID of the current scan to compare against baseline

        Returns:
            ScanComparison with new/fixed findings, risk changes, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If comparison references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"baseline_id": baseline_id, "current_id": current_id},
        )
        data = response.json()

        comparison = ScanComparison(**data)

        # Validate evidence grounding
        self._validate_comparison_grounding(comparison)

        return comparison

    async def stream_compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"baseline_id": baseline_id, "current_id": current_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Grounding Validation Helpers ====================

    def _validate_explanation_grounding(self, explanation: LlmExplanation) -> None:
        """Validate that explanation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in explanation.evidence_references}

        # Check root_cause and security_impact have evidence references
        for field_name, field_value in [
            ("root_cause", explanation.root_cause),
            ("security_impact", explanation.security_impact),
        ]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Explanation {field_name} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check attack scenarios
        for scenario in explanation.attack_scenarios:
            for eid in scenario.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Attack scenario references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_correlation_grounding(self, correlation: LlmCorrelation) -> None:
        """Validate that correlation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in correlation.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(correlation.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Correlation risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check each correlation group
        for group in correlation.correlations:
            for eid in group.shared_evidence_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Correlation group references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            # Check relationship and combined_risk
            for field_value in [group.relationship, group.combined_risk, group.mitigation_approach]:
                referenced_ids = self._extract_evidence_ids(field_value)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Correlation group field references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_remediation_grounding(self, remediation: LlmRemediation) -> None:
        """Validate that remediation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in remediation.evidence_references}

        # Check summary
        referenced_ids = self._extract_evidence_ids(remediation.summary)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Remediation summary references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check steps
        for step in remediation.steps:
            for eid in step.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Remediation step {step.step_number} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if step.rationale:
                referenced_ids = self._extract_evidence_ids(step.rationale)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Remediation step {step.step_number} rationale references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check code examples
        for example in remediation.code_examples:
            for eid in example.vulnerability_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Code example references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if example.explanation:
                referenced_ids = self._extract_evidence_ids(example.explanation)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Code example explanation references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check verification steps
        for vstep in remediation.verification_steps:
            for eid in vstep.confirmation_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Verification step references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technology guidance
        for tech in remediation.technology_guidance:
            for eid in tech.related_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Technology guidance for {tech.technology} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_summary_grounding(self, summary: ExecutiveSummary) -> None:
        """Validate that executive summary claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in summary.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(summary.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Summary risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check recommended_actions
        for action in summary.recommended_actions:
            referenced_ids = self._extract_evidence_ids(action)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Recommended action references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check business_impact
        if summary.business_impact:
            referenced_ids = self._extract_evidence_ids(summary.business_impact)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Business impact references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technical_details
        if summary.technical_details:
            for detail in summary.technical_details:
                referenced_ids = self._extract_evidence_ids(detail)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Technical detail references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_comparison_grounding(self, comparison: ScanComparison) -> None:
        """Validate that scan comparison claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in comparison.evidence_references}

        # Check summary and security_posture_assessment
        for field_value in [comparison.summary, comparison.security_posture_assessment]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Comparison field references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check increased_risk
        for risk in comparison.increased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Increased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check decreased_risk
        for risk in comparison.decreased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Decreased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract evidence IDs from text in [Evidence: <id>] format."""
        import re
        pattern = r"\[Evidence:\s*([^\]]+)\]"
        matches = re.findall(pattern, text)
        return [match.strip() for match in matches]

    async def prioritize_findings(
        self,
        scan_id: str,
    ) -> Dict[str, Any]:
        """Prioritize findings for remediation."""
        response = await self._request(
            "POST",
            "/api/analyst/prioritize",
            json={"scan_id": scan_id},
        )
        return response.json()

    async def stream_prioritize_findings(
        self,
        scan_id: str,
    ) -> AsyncIterator[str]:
        """Stream prioritization of findings for remediation."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/prioritize/stream"
            params = {"scan_id": scan_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Phase 8: Evidence-Grounded LLM Service ====================

    async def explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> LlmExplanation:
        """
        Explain a security finding with evidence grounding.

        Args:
            finding_id: The ID of the finding to explain
            require_evidence: If True, validates that all claims reference evidence IDs

        Returns:
            LlmExplanation with grounded root cause, impact, attack scenarios, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If require_evidence=True and response has ungrounded claims
        """
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"finding_id": finding_id, "require_evidence": require_evidence},
        )
        data = response.json()

        explanation = LlmExplanation(**data)

        # Validate evidence grounding if required
        if require_evidence:
            self._validate_explanation_grounding(explanation)

        return explanation

    async def stream_explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"finding_id": finding_id, "require_evidence": str(require_evidence).lower()}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> LlmCorrelation:
        """
        Correlate findings based on shared evidence.

        Args:
            finding_ids: List of finding IDs to correlate
            min_confidence: Minimum confidence threshold for correlations (0.0-1.0)

        Returns:
            LlmCorrelation with grouped findings sharing evidence, risk assessment, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If correlations reference non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"finding_ids": finding_ids, "min_confidence": min_confidence},
        )
        data = response.json()

        correlation = LlmCorrelation(**data)

        # Validate evidence grounding
        self._validate_correlation_grounding(correlation)

        return correlation

    async def stream_correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"finding_ids": json.dumps(finding_ids), "min_confidence": str(min_confidence)}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> LlmRemediation:
        """
        Generate remediation plan grounded in finding evidence + technology context.

        Args:
            finding_id: The ID of the finding to remediate
            context: Optional additional context (technology stack, compliance requirements, etc.)

        Returns:
            LlmRemediation with steps, code examples, verification steps, technology guidance, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If remediation references non-existent evidence IDs
        """
        payload = {"finding_id": finding_id}
        if context:
            payload["context"] = context

        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json=payload,
        )
        data = response.json()

        remediation = LlmRemediation(**data)

        # Validate evidence grounding
        self._validate_remediation_grounding(remediation)

        return remediation

    async def stream_suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"finding_id": finding_id}
            if context:
                params["context"] = json.dumps(context)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> ExecutiveSummary:
        """
        Generate executive summary with evidence grounding.

        Args:
            scan_id: The ID of the scan to summarize
            max_findings: Maximum number of findings to include (default: 10)
            audience: Target audience - "developer", "security_engineer", "manager", "executive" (default: "executive")

        Returns:
            ExecutiveSummary with key findings, risk assessment, recommended actions, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If summary references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "max_findings": max_findings, "audience": audience},
        )
        data = response.json()

        summary = ExecutiveSummary(**data)

        # Validate evidence grounding
        self._validate_summary_grounding(summary)

        return summary

    async def stream_executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "max_findings": str(max_findings), "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> ScanComparison:
        """
        Compare two scans for changes with evidence grounding.

        Args:
            baseline_id: The ID of the baseline scan
            current_id: The ID of the current scan to compare against baseline

        Returns:
            ScanComparison with new/fixed findings, risk changes, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If comparison references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"baseline_id": baseline_id, "current_id": current_id},
        )
        data = response.json()

        comparison = ScanComparison(**data)

        # Validate evidence grounding
        self._validate_comparison_grounding(comparison)

        return comparison

    async def stream_compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"baseline_id": baseline_id, "current_id": current_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Grounding Validation Helpers ====================

    def _validate_explanation_grounding(self, explanation: LlmExplanation) -> None:
        """Validate that explanation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in explanation.evidence_references}

        # Check root_cause and security_impact have evidence references
        for field_name, field_value in [
            ("root_cause", explanation.root_cause),
            ("security_impact", explanation.security_impact),
        ]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Explanation {field_name} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check attack scenarios
        for scenario in explanation.attack_scenarios:
            for eid in scenario.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Attack scenario references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_correlation_grounding(self, correlation: LlmCorrelation) -> None:
        """Validate that correlation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in correlation.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(correlation.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Correlation risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check each correlation group
        for group in correlation.correlations:
            for eid in group.shared_evidence_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Correlation group references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            # Check relationship and combined_risk
            for field_value in [group.relationship, group.combined_risk, group.mitigation_approach]:
                referenced_ids = self._extract_evidence_ids(field_value)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Correlation group field references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_remediation_grounding(self, remediation: LlmRemediation) -> None:
        """Validate that remediation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in remediation.evidence_references}

        # Check summary
        referenced_ids = self._extract_evidence_ids(remediation.summary)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Remediation summary references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check steps
        for step in remediation.steps:
            for eid in step.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Remediation step {step.step_number} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if step.rationale:
                referenced_ids = self._extract_evidence_ids(step.rationale)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Remediation step {step.step_number} rationale references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check code examples
        for example in remediation.code_examples:
            for eid in example.vulnerability_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Code example references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if example.explanation:
                referenced_ids = self._extract_evidence_ids(example.explanation)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Code example explanation references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check verification steps
        for vstep in remediation.verification_steps:
            for eid in vstep.confirmation_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Verification step references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technology guidance
        for tech in remediation.technology_guidance:
            for eid in tech.related_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Technology guidance for {tech.technology} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_summary_grounding(self, summary: ExecutiveSummary) -> None:
        """Validate that executive summary claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in summary.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(summary.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Summary risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check recommended_actions
        for action in summary.recommended_actions:
            referenced_ids = self._extract_evidence_ids(action)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Recommended action references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check business_impact
        if summary.business_impact:
            referenced_ids = self._extract_evidence_ids(summary.business_impact)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Business impact references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technical_details
        if summary.technical_details:
            for detail in summary.technical_details:
                referenced_ids = self._extract_evidence_ids(detail)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Technical detail references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_comparison_grounding(self, comparison: ScanComparison) -> None:
        """Validate that scan comparison claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in comparison.evidence_references}

        # Check summary and security_posture_assessment
        for field_value in [comparison.summary, comparison.security_posture_assessment]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Comparison field references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check increased_risk
        for risk in comparison.increased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Increased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check decreased_risk
        for risk in comparison.decreased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Decreased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract evidence IDs from text in [Evidence: <id>] format."""
        import re
        pattern = r"\[Evidence:\s*([^\]]+)\]"
        matches = re.findall(pattern, text)
        return [match.strip() for match in matches]

    async def executive_summary(
        self,
        scan_id: str,
        audience: str,  # "developer", "security_engineer", "manager", "executive"
    ) -> Dict[str, Any]:
        """Generate executive summary for different audiences."""
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "audience": audience},
        )
        return response.json()

    async def stream_executive_summary(
        self,
        scan_id: str,
        audience: str,  # "developer", "security_engineer", "manager", "executive"
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary for different audiences."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Phase 8: Evidence-Grounded LLM Service ====================

    async def explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> LlmExplanation:
        """
        Explain a security finding with evidence grounding.

        Args:
            finding_id: The ID of the finding to explain
            require_evidence: If True, validates that all claims reference evidence IDs

        Returns:
            LlmExplanation with grounded root cause, impact, attack scenarios, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If require_evidence=True and response has ungrounded claims
        """
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"finding_id": finding_id, "require_evidence": require_evidence},
        )
        data = response.json()

        explanation = LlmExplanation(**data)

        # Validate evidence grounding if required
        if require_evidence:
            self._validate_explanation_grounding(explanation)

        return explanation

    async def stream_explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"finding_id": finding_id, "require_evidence": str(require_evidence).lower()}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> LlmCorrelation:
        """
        Correlate findings based on shared evidence.

        Args:
            finding_ids: List of finding IDs to correlate
            min_confidence: Minimum confidence threshold for correlations (0.0-1.0)

        Returns:
            LlmCorrelation with grouped findings sharing evidence, risk assessment, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If correlations reference non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"finding_ids": finding_ids, "min_confidence": min_confidence},
        )
        data = response.json()

        correlation = LlmCorrelation(**data)

        # Validate evidence grounding
        self._validate_correlation_grounding(correlation)

        return correlation

    async def stream_correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"finding_ids": json.dumps(finding_ids), "min_confidence": str(min_confidence)}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> LlmRemediation:
        """
        Generate remediation plan grounded in finding evidence + technology context.

        Args:
            finding_id: The ID of the finding to remediate
            context: Optional additional context (technology stack, compliance requirements, etc.)

        Returns:
            LlmRemediation with steps, code examples, verification steps, technology guidance, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If remediation references non-existent evidence IDs
        """
        payload = {"finding_id": finding_id}
        if context:
            payload["context"] = context

        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json=payload,
        )
        data = response.json()

        remediation = LlmRemediation(**data)

        # Validate evidence grounding
        self._validate_remediation_grounding(remediation)

        return remediation

    async def stream_suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"finding_id": finding_id}
            if context:
                params["context"] = json.dumps(context)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> ExecutiveSummary:
        """
        Generate executive summary with evidence grounding.

        Args:
            scan_id: The ID of the scan to summarize
            max_findings: Maximum number of findings to include (default: 10)
            audience: Target audience - "developer", "security_engineer", "manager", "executive" (default: "executive")

        Returns:
            ExecutiveSummary with key findings, risk assessment, recommended actions, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If summary references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "max_findings": max_findings, "audience": audience},
        )
        data = response.json()

        summary = ExecutiveSummary(**data)

        # Validate evidence grounding
        self._validate_summary_grounding(summary)

        return summary

    async def stream_executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "max_findings": str(max_findings), "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> ScanComparison:
        """
        Compare two scans for changes with evidence grounding.

        Args:
            baseline_id: The ID of the baseline scan
            current_id: The ID of the current scan to compare against baseline

        Returns:
            ScanComparison with new/fixed findings, risk changes, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If comparison references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"baseline_id": baseline_id, "current_id": current_id},
        )
        data = response.json()

        comparison = ScanComparison(**data)

        # Validate evidence grounding
        self._validate_comparison_grounding(comparison)

        return comparison

    async def stream_compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"baseline_id": baseline_id, "current_id": current_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Grounding Validation Helpers ====================

    def _validate_explanation_grounding(self, explanation: LlmExplanation) -> None:
        """Validate that explanation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in explanation.evidence_references}

        # Check root_cause and security_impact have evidence references
        for field_name, field_value in [
            ("root_cause", explanation.root_cause),
            ("security_impact", explanation.security_impact),
        ]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Explanation {field_name} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check attack scenarios
        for scenario in explanation.attack_scenarios:
            for eid in scenario.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Attack scenario references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_correlation_grounding(self, correlation: LlmCorrelation) -> None:
        """Validate that correlation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in correlation.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(correlation.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Correlation risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check each correlation group
        for group in correlation.correlations:
            for eid in group.shared_evidence_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Correlation group references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            # Check relationship and combined_risk
            for field_value in [group.relationship, group.combined_risk, group.mitigation_approach]:
                referenced_ids = self._extract_evidence_ids(field_value)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Correlation group field references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_remediation_grounding(self, remediation: LlmRemediation) -> None:
        """Validate that remediation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in remediation.evidence_references}

        # Check summary
        referenced_ids = self._extract_evidence_ids(remediation.summary)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Remediation summary references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check steps
        for step in remediation.steps:
            for eid in step.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Remediation step {step.step_number} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if step.rationale:
                referenced_ids = self._extract_evidence_ids(step.rationale)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Remediation step {step.step_number} rationale references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check code examples
        for example in remediation.code_examples:
            for eid in example.vulnerability_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Code example references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if example.explanation:
                referenced_ids = self._extract_evidence_ids(example.explanation)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Code example explanation references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check verification steps
        for vstep in remediation.verification_steps:
            for eid in vstep.confirmation_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Verification step references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technology guidance
        for tech in remediation.technology_guidance:
            for eid in tech.related_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Technology guidance for {tech.technology} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_summary_grounding(self, summary: ExecutiveSummary) -> None:
        """Validate that executive summary claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in summary.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(summary.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Summary risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check recommended_actions
        for action in summary.recommended_actions:
            referenced_ids = self._extract_evidence_ids(action)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Recommended action references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check business_impact
        if summary.business_impact:
            referenced_ids = self._extract_evidence_ids(summary.business_impact)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Business impact references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technical_details
        if summary.technical_details:
            for detail in summary.technical_details:
                referenced_ids = self._extract_evidence_ids(detail)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Technical detail references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_comparison_grounding(self, comparison: ScanComparison) -> None:
        """Validate that scan comparison claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in comparison.evidence_references}

        # Check summary and security_posture_assessment
        for field_value in [comparison.summary, comparison.security_posture_assessment]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Comparison field references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check increased_risk
        for risk in comparison.increased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Increased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check decreased_risk
        for risk in comparison.decreased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Decreased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract evidence IDs from text in [Evidence: <id>] format."""
        import re
        pattern = r"\[Evidence:\s*([^\]]+)\]"
        matches = re.findall(pattern, text)
        return [match.strip() for match in matches]

    async def query_findings(
        self,
        scan_id: str,
        question: str,
    ) -> Dict[str, Any]:
        """Query findings with natural language."""
        response = await self._request(
            "POST",
            "/api/analyst/query",
            json={"scan_id": scan_id, "question": question},
        )
        return response.json()

    async def stream_query_findings(
        self,
        scan_id: str,
        question: str,
    ) -> AsyncIterator[str]:
        """Stream querying of findings with natural language."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/query/stream"
            params = {"scan_id": scan_id, "question": question}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Phase 8: Evidence-Grounded LLM Service ====================

    async def explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> LlmExplanation:
        """
        Explain a security finding with evidence grounding.

        Args:
            finding_id: The ID of the finding to explain
            require_evidence: If True, validates that all claims reference evidence IDs

        Returns:
            LlmExplanation with grounded root cause, impact, attack scenarios, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If require_evidence=True and response has ungrounded claims
        """
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"finding_id": finding_id, "require_evidence": require_evidence},
        )
        data = response.json()

        explanation = LlmExplanation(**data)

        # Validate evidence grounding if required
        if require_evidence:
            self._validate_explanation_grounding(explanation)

        return explanation

    async def stream_explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"finding_id": finding_id, "require_evidence": str(require_evidence).lower()}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> LlmCorrelation:
        """
        Correlate findings based on shared evidence.

        Args:
            finding_ids: List of finding IDs to correlate
            min_confidence: Minimum confidence threshold for correlations (0.0-1.0)

        Returns:
            LlmCorrelation with grouped findings sharing evidence, risk assessment, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If correlations reference non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"finding_ids": finding_ids, "min_confidence": min_confidence},
        )
        data = response.json()

        correlation = LlmCorrelation(**data)

        # Validate evidence grounding
        self._validate_correlation_grounding(correlation)

        return correlation

    async def stream_correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"finding_ids": json.dumps(finding_ids), "min_confidence": str(min_confidence)}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> LlmRemediation:
        """
        Generate remediation plan grounded in finding evidence + technology context.

        Args:
            finding_id: The ID of the finding to remediate
            context: Optional additional context (technology stack, compliance requirements, etc.)

        Returns:
            LlmRemediation with steps, code examples, verification steps, technology guidance, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If remediation references non-existent evidence IDs
        """
        payload = {"finding_id": finding_id}
        if context:
            payload["context"] = context

        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json=payload,
        )
        data = response.json()

        remediation = LlmRemediation(**data)

        # Validate evidence grounding
        self._validate_remediation_grounding(remediation)

        return remediation

    async def stream_suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"finding_id": finding_id}
            if context:
                params["context"] = json.dumps(context)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> ExecutiveSummary:
        """
        Generate executive summary with evidence grounding.

        Args:
            scan_id: The ID of the scan to summarize
            max_findings: Maximum number of findings to include (default: 10)
            audience: Target audience - "developer", "security_engineer", "manager", "executive" (default: "executive")

        Returns:
            ExecutiveSummary with key findings, risk assessment, recommended actions, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If summary references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "max_findings": max_findings, "audience": audience},
        )
        data = response.json()

        summary = ExecutiveSummary(**data)

        # Validate evidence grounding
        self._validate_summary_grounding(summary)

        return summary

    async def stream_executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "max_findings": str(max_findings), "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> ScanComparison:
        """
        Compare two scans for changes with evidence grounding.

        Args:
            baseline_id: The ID of the baseline scan
            current_id: The ID of the current scan to compare against baseline

        Returns:
            ScanComparison with new/fixed findings, risk changes, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If comparison references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"baseline_id": baseline_id, "current_id": current_id},
        )
        data = response.json()

        comparison = ScanComparison(**data)

        # Validate evidence grounding
        self._validate_comparison_grounding(comparison)

        return comparison

    async def stream_compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"baseline_id": baseline_id, "current_id": current_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Grounding Validation Helpers ====================

    def _validate_explanation_grounding(self, explanation: LlmExplanation) -> None:
        """Validate that explanation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in explanation.evidence_references}

        # Check root_cause and security_impact have evidence references
        for field_name, field_value in [
            ("root_cause", explanation.root_cause),
            ("security_impact", explanation.security_impact),
        ]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Explanation {field_name} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check attack scenarios
        for scenario in explanation.attack_scenarios:
            for eid in scenario.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Attack scenario references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_correlation_grounding(self, correlation: LlmCorrelation) -> None:
        """Validate that correlation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in correlation.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(correlation.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Correlation risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check each correlation group
        for group in correlation.correlations:
            for eid in group.shared_evidence_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Correlation group references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            # Check relationship and combined_risk
            for field_value in [group.relationship, group.combined_risk, group.mitigation_approach]:
                referenced_ids = self._extract_evidence_ids(field_value)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Correlation group field references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_remediation_grounding(self, remediation: LlmRemediation) -> None:
        """Validate that remediation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in remediation.evidence_references}

        # Check summary
        referenced_ids = self._extract_evidence_ids(remediation.summary)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Remediation summary references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check steps
        for step in remediation.steps:
            for eid in step.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Remediation step {step.step_number} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if step.rationale:
                referenced_ids = self._extract_evidence_ids(step.rationale)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Remediation step {step.step_number} rationale references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check code examples
        for example in remediation.code_examples:
            for eid in example.vulnerability_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Code example references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if example.explanation:
                referenced_ids = self._extract_evidence_ids(example.explanation)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Code example explanation references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check verification steps
        for vstep in remediation.verification_steps:
            for eid in vstep.confirmation_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Verification step references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technology guidance
        for tech in remediation.technology_guidance:
            for eid in tech.related_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Technology guidance for {tech.technology} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_summary_grounding(self, summary: ExecutiveSummary) -> None:
        """Validate that executive summary claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in summary.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(summary.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Summary risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check recommended_actions
        for action in summary.recommended_actions:
            referenced_ids = self._extract_evidence_ids(action)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Recommended action references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check business_impact
        if summary.business_impact:
            referenced_ids = self._extract_evidence_ids(summary.business_impact)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Business impact references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technical_details
        if summary.technical_details:
            for detail in summary.technical_details:
                referenced_ids = self._extract_evidence_ids(detail)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Technical detail references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_comparison_grounding(self, comparison: ScanComparison) -> None:
        """Validate that scan comparison claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in comparison.evidence_references}

        # Check summary and security_posture_assessment
        for field_value in [comparison.summary, comparison.security_posture_assessment]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Comparison field references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check increased_risk
        for risk in comparison.increased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Increased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check decreased_risk
        for risk in comparison.decreased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Decreased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract evidence IDs from text in [Evidence: <id>] format."""
        import re
        pattern = r"\[Evidence:\s*([^\]]+)\]"
        matches = re.findall(pattern, text)
        return [match.strip() for match in matches]

    async def compare_scans(
        self,
        base_scan_id: str,
        target_scan_id: str,
    ) -> Dict[str, Any]:
        """Compare two scans for changes."""
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"base_scan_id": base_scan_id, "target_scan_id": target_scan_id},
        )
        return response.json()

    async def stream_compare_scans(
        self,
        base_scan_id: str,
        target_scan_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans for changes."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"base_scan_id": base_scan_id, "target_scan_id": target_scan_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Phase 8: Evidence-Grounded LLM Service ====================

    async def explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> LlmExplanation:
        """
        Explain a security finding with evidence grounding.

        Args:
            finding_id: The ID of the finding to explain
            require_evidence: If True, validates that all claims reference evidence IDs

        Returns:
            LlmExplanation with grounded root cause, impact, attack scenarios, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If require_evidence=True and response has ungrounded claims
        """
        response = await self._request(
            "POST",
            "/api/analyst/explain",
            json={"finding_id": finding_id, "require_evidence": require_evidence},
        )
        data = response.json()

        explanation = LlmExplanation(**data)

        # Validate evidence grounding if required
        if require_evidence:
            self._validate_explanation_grounding(explanation)

        return explanation

    async def stream_explain_finding(
        self,
        finding_id: str,
        require_evidence: bool = True,
    ) -> AsyncIterator[str]:
        """Stream explanation of a security finding with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/explain/stream"
            params = {"finding_id": finding_id, "require_evidence": str(require_evidence).lower()}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> LlmCorrelation:
        """
        Correlate findings based on shared evidence.

        Args:
            finding_ids: List of finding IDs to correlate
            min_confidence: Minimum confidence threshold for correlations (0.0-1.0)

        Returns:
            LlmCorrelation with grouped findings sharing evidence, risk assessment, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If correlations reference non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/correlate",
            json={"finding_ids": finding_ids, "min_confidence": min_confidence},
        )
        data = response.json()

        correlation = LlmCorrelation(**data)

        # Validate evidence grounding
        self._validate_correlation_grounding(correlation)

        return correlation

    async def stream_correlate_findings(
        self,
        finding_ids: List[str],
        min_confidence: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream correlation of findings with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/correlate/stream"
            params = {"finding_ids": json.dumps(finding_ids), "min_confidence": str(min_confidence)}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> LlmRemediation:
        """
        Generate remediation plan grounded in finding evidence + technology context.

        Args:
            finding_id: The ID of the finding to remediate
            context: Optional additional context (technology stack, compliance requirements, etc.)

        Returns:
            LlmRemediation with steps, code examples, verification steps, technology guidance, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If remediation references non-existent evidence IDs
        """
        payload = {"finding_id": finding_id}
        if context:
            payload["context"] = context

        response = await self._request(
            "POST",
            "/api/analyst/remediate",
            json=payload,
        )
        data = response.json()

        remediation = LlmRemediation(**data)

        # Validate evidence grounding
        self._validate_remediation_grounding(remediation)

        return remediation

    async def stream_suggest_remediation(
        self,
        finding_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        """Stream generation of remediation plan with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/remediate/stream"
            params = {"finding_id": finding_id}
            if context:
                params["context"] = json.dumps(context)

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> ExecutiveSummary:
        """
        Generate executive summary with evidence grounding.

        Args:
            scan_id: The ID of the scan to summarize
            max_findings: Maximum number of findings to include (default: 10)
            audience: Target audience - "developer", "security_engineer", "manager", "executive" (default: "executive")

        Returns:
            ExecutiveSummary with key findings, risk assessment, recommended actions, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If summary references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/summarize",
            json={"scan_id": scan_id, "max_findings": max_findings, "audience": audience},
        )
        data = response.json()

        summary = ExecutiveSummary(**data)

        # Validate evidence grounding
        self._validate_summary_grounding(summary)

        return summary

    async def stream_executive_summary(
        self,
        scan_id: str,
        max_findings: int = 10,
        audience: str = "executive",
    ) -> AsyncIterator[str]:
        """Stream generation of executive summary with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/summarize/stream"
            params = {"scan_id": scan_id, "max_findings": str(max_findings), "audience": audience}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    async def compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> ScanComparison:
        """
        Compare two scans for changes with evidence grounding.

        Args:
            baseline_id: The ID of the baseline scan
            current_id: The ID of the current scan to compare against baseline

        Returns:
            ScanComparison with new/fixed findings, risk changes, and evidence references

        Raises:
            httpx.HTTPStatusError: If the API returns an error
            ValueError: If comparison references non-existent evidence IDs
        """
        response = await self._request(
            "POST",
            "/api/analyst/compare",
            json={"baseline_id": baseline_id, "current_id": current_id},
        )
        data = response.json()

        comparison = ScanComparison(**data)

        # Validate evidence grounding
        self._validate_comparison_grounding(comparison)

        return comparison

    async def stream_compare_scans(
        self,
        baseline_id: str,
        current_id: str,
    ) -> AsyncIterator[str]:
        """Stream comparison of two scans with evidence grounding."""
        import json
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{self.base_url}/api/analyst/compare/stream"
            params = {"baseline_id": baseline_id, "current_id": current_id}

            if self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            elif self._tokens:
                headers = {"Authorization": f"Bearer {self._tokens.access_token}"}
            else:
                headers = {}

            async with client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]  # Remove "data: " prefix
                        if data.strip() == "[DONE]":
                            break
                        yield data

    # ==================== Grounding Validation Helpers ====================

    def _validate_explanation_grounding(self, explanation: LlmExplanation) -> None:
        """Validate that explanation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in explanation.evidence_references}

        # Check root_cause and security_impact have evidence references
        for field_name, field_value in [
            ("root_cause", explanation.root_cause),
            ("security_impact", explanation.security_impact),
        ]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Explanation {field_name} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check attack scenarios
        for scenario in explanation.attack_scenarios:
            for eid in scenario.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Attack scenario references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_correlation_grounding(self, correlation: LlmCorrelation) -> None:
        """Validate that correlation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in correlation.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(correlation.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Correlation risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check each correlation group
        for group in correlation.correlations:
            for eid in group.shared_evidence_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Correlation group references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            # Check relationship and combined_risk
            for field_value in [group.relationship, group.combined_risk, group.mitigation_approach]:
                referenced_ids = self._extract_evidence_ids(field_value)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Correlation group field references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_remediation_grounding(self, remediation: LlmRemediation) -> None:
        """Validate that remediation claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in remediation.evidence_references}

        # Check summary
        referenced_ids = self._extract_evidence_ids(remediation.summary)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Remediation summary references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check steps
        for step in remediation.steps:
            for eid in step.supporting_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Remediation step {step.step_number} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if step.rationale:
                referenced_ids = self._extract_evidence_ids(step.rationale)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Remediation step {step.step_number} rationale references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check code examples
        for example in remediation.code_examples:
            for eid in example.vulnerability_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Code example references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )
            if example.explanation:
                referenced_ids = self._extract_evidence_ids(example.explanation)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Code example explanation references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

        # Check verification steps
        for vstep in remediation.verification_steps:
            for eid in vstep.confirmation_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Verification step references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technology guidance
        for tech in remediation.technology_guidance:
            for eid in tech.related_evidence:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Technology guidance for {tech.technology} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _validate_summary_grounding(self, summary: ExecutiveSummary) -> None:
        """Validate that executive summary claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in summary.evidence_references}

        # Check risk_assessment
        referenced_ids = self._extract_evidence_ids(summary.risk_assessment)
        for eid in referenced_ids:
            if eid not in all_evidence_ids:
                raise ValueError(
                    f"Summary risk_assessment references unknown evidence ID: {eid}. "
                    f"Available: {list(all_evidence_ids)}"
                )

        # Check recommended_actions
        for action in summary.recommended_actions:
            referenced_ids = self._extract_evidence_ids(action)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Recommended action references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check business_impact
        if summary.business_impact:
            referenced_ids = self._extract_evidence_ids(summary.business_impact)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Business impact references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check technical_details
        if summary.technical_details:
            for detail in summary.technical_details:
                referenced_ids = self._extract_evidence_ids(detail)
                for eid in referenced_ids:
                    if eid not in all_evidence_ids:
                        raise ValueError(
                            f"Technical detail references unknown evidence ID: {eid}. "
                            f"Available: {list(all_evidence_ids)}"
                        )

    def _validate_comparison_grounding(self, comparison: ScanComparison) -> None:
        """Validate that scan comparison claims are grounded in evidence references."""
        all_evidence_ids = {ref.evidence_id for ref in comparison.evidence_references}

        # Check summary and security_posture_assessment
        for field_value in [comparison.summary, comparison.security_posture_assessment]:
            referenced_ids = self._extract_evidence_ids(field_value)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Comparison field references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check increased_risk
        for risk in comparison.increased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Increased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

        # Check decreased_risk
        for risk in comparison.decreased_risk:
            referenced_ids = self._extract_evidence_ids(risk.description)
            for eid in referenced_ids:
                if eid not in all_evidence_ids:
                    raise ValueError(
                        f"Decreased risk for {risk.finding_id} references unknown evidence ID: {eid}. "
                        f"Available: {list(all_evidence_ids)}"
                    )

    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract evidence IDs from text in [Evidence: <id>] format."""
        import re
        pattern = r"\[Evidence:\s*([^\]]+)\]"
        matches = re.findall(pattern, text)
        return [match.strip() for match in matches]