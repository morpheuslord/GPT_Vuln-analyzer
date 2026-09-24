"""Typed result schemas for GVA's AI analysis.

These Pydantic models are the structured-output contract the AI agents must
return, so downstream code gets validated objects instead of hand-parsed text.
"""
from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class NmapAnalysis(BaseModel):
    critical_score: str = Field("", description="Overall criticality from CVEs or exposed services")
    os_information: str = Field("", description="Operating system details of the target")
    open_ports: str = Field("", description="Open ports found")
    open_services: str = Field("", description="Services running on the open ports")
    vulnerable_service: str = Field("", description="Services that appear vulnerable")
    found_cve: str = Field("", description="CVEs identified, with a short note each")


class DNSRecords(BaseModel):
    A: List[str] = Field(default_factory=list)
    AAAA: List[str] = Field(default_factory=list)
    NS: List[str] = Field(default_factory=list)
    MX: List[str] = Field(default_factory=list)
    PTR: List[str] = Field(default_factory=list)
    SOA: List[str] = Field(default_factory=list)
    TXT: List[str] = Field(default_factory=list)


class ReverseDNS(BaseModel):
    IP_Address: str = ""
    Domain: str = ""


class ZoneTransferScan(BaseModel):
    Allowed: bool = False
    Name_Servers: List[str] = Field(default_factory=list)


class DNSAnalysis(BaseModel):
    DNS_Records: DNSRecords = Field(default_factory=DNSRecords)
    Reverse_DNS: ReverseDNS = Field(default_factory=ReverseDNS)
    Zone_Transfer_Scan: ZoneTransferScan = Field(default_factory=ZoneTransferScan)


class JWTAnalysis(BaseModel):
    Algorithm_Used: str = ""
    Header: str = ""
    Payload: str = ""
    Signature: str = ""
    PossibleAttacks: str = Field("", description="Realistic JWT attacks worth attempting")
    VulnerableEndpoints: str = Field("", description="Endpoints worth testing with this token")


SCAN_SCHEMAS = {
    "nmap": NmapAnalysis,
    "dns": DNSAnalysis,
    "jwt": JWTAnalysis,
}
