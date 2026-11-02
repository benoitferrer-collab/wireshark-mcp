"""Shared validated search schema; included in the standalone gateway image."""
import ipaddress
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

def normalize_indicator(value):
    value = value.strip()
    try:
        return 'ip', str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        domain = value.rstrip('.').encode('idna').decode('ascii').lower()
        if len(domain) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', domain):
            raise ValueError('Use an IP, CIDR or DNS domain') from None
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in domain.split('.')):
            raise ValueError('Invalid domain')
        return 'domain', domain


def indicator_filter(value):
    kind, value = normalize_indicator(value)
    if kind == 'ip':
        family = 'ipv6' if ':' in value else 'ip'
        answer='dns.aaaa' if family=='ipv6' else 'dns.a'
        return f'({family}.addr == {value} || {answer} == {value})'
    # Anchored, escaped domain boundaries; compatible with supported TShark versions.
    pattern = r'(^|\.)' + re.escape(value) + r'\.?$'
    return '(' + ' || '.join(
        f'lower({field}) matches r"{pattern}"'
        for field in ('dns.qry.name', 'tls.handshake.extensions_server_name', 'http.host')) + ')'


class SearchFilters(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    ip: str | None = Field(None, max_length=100)
    src_ip: str | None = Field(None, max_length=100)
    dst_ip: str | None = Field(None, max_length=100)
    port: int | None = Field(None, ge=0, le=65535)
    src_port: int | None = Field(None, ge=0, le=65535)
    dst_port: int | None = Field(None, ge=0, le=65535)
    protocol: Literal['tcp','udp','dns','http','tls','icmp','icmpv6','arp','smb','smb2','kerberos','ldap','ssh','rdp'] | None = None
    domain: str | None = Field(None, max_length=253)
    time_start: float | None = Field(None, ge=0, description='Inclusive Unix epoch seconds')
    time_end: float | None = Field(None, ge=0, description='Inclusive Unix epoch seconds')
    tcp_stream: int | None = Field(None, ge=0, le=2147483647)
    display_filter: str | None = Field(None, max_length=1024)

    @field_validator('ip','src_ip','dst_ip')
    @classmethod
    def validate_ip(cls,v):
        return str(ipaddress.ip_network(v,strict=False)) if v is not None else None

    @field_validator('domain')
    @classmethod
    def validate_domain(cls,v):
        if v is not None and normalize_indicator(v)[0] != 'domain': raise ValueError('Expected a DNS domain')
        return normalize_indicator(v)[1] if v is not None else None

    @field_validator('display_filter')
    @classmethod
    def validate_display_filter(cls,v):
        if v is not None and (not v.strip() or any(ord(c)<32 or c in '@$`' for c in v)):
            raise ValueError('Invalid display filter: macros and control characters are disabled')
        return v

    @model_validator(mode='after')
    def validate_times(self):
        if self.time_start is not None and self.time_end is not None and self.time_end < self.time_start:
            raise ValueError('time_end must be >= time_start')
        return self

    def expression(self):
        terms=[]
        for name,direction in (('ip','addr'),('src_ip','src'),('dst_ip','dst')):
            value=getattr(self,name)
            if value: terms.append(f'{"ipv6" if ":" in value else "ip"}.{direction} == {value}')
        for name,direction in (('port','port'),('src_port','srcport'),('dst_port','dstport')):
            value=getattr(self,name)
            if value is not None: terms.append(f'(tcp.{direction} == {value} || udp.{direction} == {value})')
        if self.protocol: terms.append(self.protocol)
        if self.domain: terms.append(indicator_filter(self.domain))
        if self.time_start is not None: terms.append(f'frame.time_epoch >= {self.time_start}')
        if self.time_end is not None: terms.append(f'frame.time_epoch <= {self.time_end}')
        if self.tcp_stream is not None: terms.append(f'tcp.stream == {self.tcp_stream}')
        if self.display_filter: terms.append(self.display_filter)
        return ' && '.join(f'({term})' for term in terms) or 'frame'

