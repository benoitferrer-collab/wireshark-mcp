import os
from urllib.parse import urlparse
from pydantic import BaseModel, Field, model_validator


class GatewaySettings(BaseModel):
    public_url: str
    backend_url: str
    backend_token: str = Field(min_length=32, repr=False)
    issuer: str
    audience: str = Field(min_length=1)
    jwks_url: str
    allowed_subjects: list[str] = Field(min_length=1)
    port: int = 8001

    @model_validator(mode='after')
    def validate_urls(self):
        for value in (self.public_url, self.issuer, self.jwks_url):
            url = urlparse(value)
            if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise ValueError('Public MCP and OAuth URLs must be absolute HTTPS URLs without credentials/query')
        if urlparse(self.public_url).path != '/mcp':
            raise ValueError('MCP_PUBLIC_URL must end in /mcp')
        backend = urlparse(self.backend_url)
        if backend.scheme not in ('http', 'https') or not backend.hostname or backend.path not in ('', '/') or backend.username or backend.password or backend.query or backend.fragment:
            raise ValueError('Backend URL must be an origin without credentials')
        if any(not sub.strip() for sub in self.allowed_subjects):
            raise ValueError('Allowed OAuth subjects cannot be empty')
        self.backend_url = self.backend_url.rstrip('/')
        return self

    @classmethod
    def from_env(cls):
        return cls(
            public_url=os.getenv('MCP_PUBLIC_URL') or ('https://' + os.environ['VERCEL_PROJECT_PRODUCTION_URL'] + '/mcp'),
            backend_url=os.getenv('MCP_BACKEND_URL', 'http://fastapi:8000'),
            backend_token=os.environ['API_ACCESS_TOKEN'],
            issuer=os.environ['MCP_OAUTH_ISSUER'],
            audience=os.environ['MCP_OAUTH_AUDIENCE'],
            jwks_url=os.environ['MCP_OAUTH_JWKS_URL'],
            allowed_subjects=[s.strip() for s in os.environ['MCP_ALLOWED_SUBJECTS'].split(',')],
            port=int(os.getenv('MCP_PORT', '8001')),
        )
