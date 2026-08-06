#!/usr/bin/env python3
"""
Example usage of the AI Security Analyst functionality in the OpenRE Python client.
"""

import asyncio
from openre.client import OpenREClient

async def main():
    # Initialize the client
    async with OpenREClient(base_url="http://localhost:8080") as client:
        # Example: Explain a security finding (non-streaming)
        print("=== Explaining Security Finding ===")
        try:
            explanation = await client.explain_finding(
                scan_id="example-scan-id",
                finding_id="example-finding-id"
            )
            print(f"Explanation: {explanation}")
        except Exception as e:
            print(f"Error explaining finding: {e}")

        # Example: Stream explanation of a security finding
        print("\n=== Streaming Explanation ===")
        try:
            async for chunk in client.stream_explain_finding(
                scan_id="example-scan-id",
                finding_id="example-finding-id"
            ):
                print(chunk, end="", flush=True)
            print()  # New line after streaming
        except Exception as e:
            print(f"Error streaming explanation: {e}")

        # Example: Generate remediation plan (non-streaming)
        print("\n=== Generating Remediation Plan ===")
        try:
            remediation = await client.generate_remediation(
                scan_id="example-scan-id",
                finding_id="example-finding-id"
            )
            print(f"Remediation: {remediation}")
        except Exception as e:
            print(f"Error generating remediation: {e}")

        # Example: Stream remediation plan generation
        print("\n=== Streaming Remediation Generation ===")
        try:
            async for chunk in client.stream_generate_remediation(
                scan_id="example-scan-id",
                finding_id="example-finding-id"
            ):
                print(chunk, end="", flush=True)
            print()  # New line after streaming
        except Exception as e:
            print(f"Error streaming remediation: {e}")

        # Example: Correlate findings (non-streaming)
        print("\n=== Correlating Findings ===")
        try:
            correlation = await client.correlate_findings(
                scan_id="example-scan-id",
                filter={"severity": ["high", "critical"]}
            )
            print(f"Correlation: {correlation}")
        except Exception as e:
            print(f"Error correlating findings: {e}")

        # Example: Prioritize findings (non-streaming)
        print("\n=== Prioritizing Findings ===")
        try:
            prioritization = await client.prioritize_findings(
                scan_id="example-scan-id"
            )
            print(f"Prioritization: {prioritization}")
        except Exception as e:
            print(f"Error prioritizing findings: {e}")

        # Example: Generate executive summary (non-streaming)
        print("\n=== Generating Executive Summary ===")
        try:
            summary = await client.executive_summary(
                scan_id="example-scan-id",
                audience="security_engineer"
            )
            print(f"Summary: {summary}")
        except Exception as e:
            print(f"Error generating summary: {e}")

        # Example: Query findings (non-streaming)
        print("\n=== Querying Findings ===")
        try:
            response = await client.query_findings(
                scan_id="example-scan-id",
                question="Show me all high severity findings"
            )
            print(f"Query Response: {response}")
        except Exception as e:
            print(f"Error querying findings: {e}")

        # Example: Compare scans (non-streaming)
        print("\n=== Comparing Scans ===")
        try:
            comparison = await client.compare_scans(
                base_scan_id="base-scan-id",
                target_scan_id="target-scan-id"
            )
            print(f"Comparison: {comparison}")
        except Exception as e:
            print(f"Error comparing scans: {e}")

if __name__ == "__main__":
    asyncio.run(main())