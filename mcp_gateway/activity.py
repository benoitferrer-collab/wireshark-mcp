"""Count authenticated tools/call only; never log tool inputs or evidence."""
import asyncio
import logging
import re
import time
from uuid import uuid4
import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.middleware.auth_context import get_access_token
logger=logging.getLogger(__name__)

class ActivityFastMCP(FastMCP):
    def __init__(self,*args,activity_sink=None,identity_reader=None,**kwargs):
        self.activity_sink=activity_sink
        self.identity_reader=identity_reader or get_access_token
        super().__init__(*args,**kwargs)

    async def call_tool(self,name,arguments):
        identity=self.identity_reader()
        started=time.monotonic()
        success=False
        try:
            result=await super().call_tool(name,arguments)
            success=not getattr(result,'isError',False)
            return result
        finally:
            if identity and self.activity_sink:
                event={'event_id':str(uuid4()),'client_id':identity.client_id,'tool':name if self._tool_manager.get_tool(name) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}',name) else 'unknown_tool','success':success,'duration_ms':min(86400000,int((time.monotonic()-started)*1000))}
                try:
                    await asyncio.wait_for(self.activity_sink(event),timeout=3)
                except Exception:
                    logger.warning('MCP activity collector unavailable')


def backend_sink(settings):
    async def record(event):
        async with httpx.AsyncClient(timeout=2,follow_redirects=False) as client:
            result=await client.post(settings.backend_url+'/api/identity/internal/activity',json=event,headers={'Authorization':'Bearer '+settings.backend_token})
            result.raise_for_status()
    return record
