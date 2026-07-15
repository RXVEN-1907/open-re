"""
Analysis manager for open-re Python bindings.
"""

from typing import Optional, List, Dict, Any, AsyncIterator
from dataclasses import dataclass
from datetime import datetime
import asyncio

from .client import OpenREClient
from .models import AnalysisJob, AnalysisResult, JobStatus


@dataclass
class AnalysisProgress:
    job_id: str
    status: JobStatus
    progress: Optional[float]
    current_stage: Optional[str]
    stages_completed: int
    total_stages: int
    error: Optional[str]


class AnalysisManager:
    """
    High-level manager for binary analysis operations.
    
    Example:
        async with OpenREClient() as client:
            await client.login("user@example.com", "password")
            manager = AnalysisManager(client)
            job = await manager.analyze_file("file-id")
            result = await manager.wait_for_completion(job.job_id)
    """
    
    def __init__(self, client: OpenREClient):
        self.client = client
    
    async def analyze_file(
        self,
        file_id: str,
        stages: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        priority: str = "default",
    ) -> AnalysisJob:
        """Start analysis on a file."""
        response = await self.client.start_analysis(file_id, stages, config, priority)
        return AnalysisJob(**response)
    
    async def get_status(self, job_id: str) -> AnalysisJob:
        """Get analysis job status."""
        response = await self.client.get_analysis_status(job_id)
        return AnalysisJob(**response)
    
    async def get_results(self, job_id: str) -> AnalysisResult:
        """Get analysis results."""
        response = await self.client.get_analysis_results(job_id)
        return AnalysisResult(**response)
    
    async def cancel(self, job_id: str) -> Dict[str, Any]:
        """Cancel analysis."""
        return await self.client.cancel_analysis(job_id)
    
    async def retry(self, job_id: str) -> AnalysisJob:
        """Retry analysis."""
        response = await self.client.retry_analysis(job_id)
        return AnalysisJob(**response)
    
    async def wait_for_completion(
        self,
        job_id: str,
        poll_interval: float = 2.0,
        timeout: Optional[float] = None,
    ) -> AnalysisResult:
        """
        Wait for analysis to complete.
        
        Args:
            job_id: The job ID to wait for
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait (None for no timeout)
        
        Returns:
            AnalysisResult when completed
        
        Raises:
            TimeoutError: If timeout is reached
            RuntimeError: If analysis fails
        """
        start_time = asyncio.get_event_loop().time()
        
        while True:
            job = await self.get_status(job_id)
            
            if job.status == JobStatus.COMPLETED:
                return await self.get_results(job_id)
            elif job.status == JobStatus.FAILED:
                raise RuntimeError(f"Analysis failed: {job.error}")
            elif job.status == JobStatus.CANCELLED:
                raise RuntimeError("Analysis was cancelled")
            
            if timeout and (asyncio.get_event_loop().time() - start_time) > timeout:
                raise TimeoutError(f"Analysis did not complete within {timeout} seconds")
            
            await asyncio.sleep(poll_interval)
    
    async def wait_for_completion_with_progress(
        self,
        job_id: str,
        poll_interval: float = 2.0,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[AnalysisProgress]:
        """
        Wait for analysis to complete, yielding progress updates.
        
        Yields:
            AnalysisProgress for each status check
        """
        start_time = asyncio.get_event_loop().time()
        
        while True:
            job = await self.get_status(job_id)
            
            yield AnalysisProgress(
                job_id=job.job_id,
                status=job.status,
                progress=job.progress,
                current_stage=job.current_stage,
                stages_completed=job.stages_completed,
                total_stages=job.total_stages,
                error=job.error,
            )
            
            if job.status == JobStatus.COMPLETED:
                result = await self.get_results(job_id)
                yield AnalysisProgress(
                    job_id=job.job_id,
                    status=job.status,
                    progress=1.0,
                    current_stage="completed",
                    stages_completed=job.total_stages,
                    total_stages=job.total_stages,
                    error=None,
                )
                return
            elif job.status == JobStatus.FAILED:
                raise RuntimeError(f"Analysis failed: {job.error}")
            elif job.status == JobStatus.CANCELLED:
                raise RuntimeError("Analysis was cancelled")
            
            if timeout and (asyncio.get_event_loop().time() - start_time) > timeout:
                raise TimeoutError(f"Analysis did not complete within {timeout} seconds")
            
            await asyncio.sleep(poll_interval)
    
    async def list_analyses(
        self,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List analyses."""
        return await self.client.list_analyses(page, per_page, status)