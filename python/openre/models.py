"""
Pydantic models for open-re API responses.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


class JobStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SCHEDULED = "scheduled"


class JobPriority(str, Enum):
    HIGH = "high"
    DEFAULT = "default"
    LOW = "low"


class FileStatus(str, Enum):
    UPLOADED = "uploaded"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class Project(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    owner_id: str
    is_public: bool
    settings: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


class File(BaseModel):
    id: str
    user_id: str
    project_id: Optional[str] = None
    filename: str
    content_type: str
    size: int
    object_id: str
    status: str
    hash: str
    created_at: datetime
    updated_at: datetime


class FunctionParameter(BaseModel):
    name: str
    type: str
    location: str


class Function(BaseModel):
    id: str
    file_id: str
    name: str
    address: int
    size: int
    is_entry: bool
    is_thunk: bool
    calling_convention: Optional[str] = None
    return_type: Optional[str] = None
    parameters: List[FunctionParameter] = []
    stack_frame_size: Optional[int] = None
    cyclomatic_complexity: Optional[int] = None
    created_at: datetime
    updated_at: datetime


class AnalysisJob(BaseModel):
    job_id: str
    job_type: str
    status: JobStatus
    progress: Optional[float] = None
    current_stage: Optional[str] = None
    stages_completed: int = 0
    total_stages: int = 0
    error: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class AnalysisResult(BaseModel):
    job_id: str
    result: Dict[str, Any]
    completed_at: datetime


class Plugin(BaseModel):
    id: str
    name: str
    version: str
    description: str
    author: str
    plugin_type: str
    capabilities: List[str]
    enabled: bool
    config: Optional[Dict[str, Any]] = None
    installed_at: datetime
    updated_at: datetime


class User(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class APIKey(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: List[str]
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    created_at: datetime


class Collaborator(BaseModel):
    user_id: str
    project_id: str
    role: str
    added_at: datetime
    user: Optional[User] = None


class Invite(BaseModel):
    id: str
    project_id: str
    email: str
    role: str
    token: str
    expires_at: datetime
    created_at: datetime
    accepted_at: Optional[datetime] = None


class ShareLink(BaseModel):
    id: str
    project_id: str
    token: str
    permission: str
    expires_at: Optional[datetime] = None
    max_uses: Optional[int] = None
    uses: int
    created_at: datetime


class Export(BaseModel):
    id: str
    project_id: str
    format: str
    status: str
    download_url: Optional[str] = None
    file_size: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class PseudocodeResponse(BaseModel):
    function_id: str
    pseudocode: str
    language: str
    generated_at: datetime


class CfgNode(BaseModel):
    id: str
    address: int
    instructions: List[str]
    is_entry: bool
    is_exit: bool


class CfgEdge(BaseModel):
    from_node: str
    to_node: str
    type: str


class CfgResponse(BaseModel):
    function_id: str
    nodes: List[CfgNode]
    edges: List[CfgEdge]


class XrefInfo(BaseModel):
    from_address: int
    to_address: int
    type: str
    from_function: Optional[str] = None
    to_function: Optional[str] = None


class XrefResponse(BaseModel):
    function_id: str
    xrefs: List[XrefInfo]


class AnnotationInfo(BaseModel):
    id: str
    type: str
    content: str
    address: Optional[int] = None
    author: str
    created_at: datetime


class AnnotationsResponse(BaseModel):
    function_id: str
    annotations: List[AnnotationInfo]


class ChatMessage(BaseModel):
    role: str
    content: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


class ChatCompletionResponse(BaseModel):
    id: str
    model: str
    choices: List[Dict[str, Any]]
    usage: Dict[str, int]
    created: int


class AnalyzeFunctionResponse(BaseModel):
    analysis: str
    model: str
    usage: Dict[str, int]


class TemplateInfo(BaseModel):
    name: str
    description: str
    variables: List[str]


class PaginatedResponse(BaseModel):
    data: List[Any]
    total: int
    page: int
    per_page: int