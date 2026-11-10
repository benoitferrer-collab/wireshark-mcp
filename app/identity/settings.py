"""Explicit opt-in; refuse a partially configured web identity deployment."""
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
from uuid import UUID
from cryptography.fernet import Fernet

@dataclass(frozen=True)
class WebSettings:
    tenant_id: str
    owner_oid: str
    client_id: str
    client_secret: str = field(repr=False)
    origin: str
    database_url: str = field(repr=False)
    encryption_key: str = field(repr=False)
    api_token: str = field(repr=False)
    cron_secret: str = field(repr=False)

    @property
    def callback_url(self): return self.origin+'/auth/callback'

    @classmethod
    def from_env(cls):
        if os.getenv('WEB_AUTH_ENABLED') != 'true': return None
        obj=cls(tenant_id=str(UUID(os.environ['WEB_ENTRA_TENANT_ID'])),owner_oid=str(UUID(os.environ['WEB_ADMIN_OID'])),client_id=str(UUID(os.environ['WEB_ENTRA_CLIENT_ID'])),client_secret=os.environ['WEB_ENTRA_CLIENT_SECRET'],origin=os.environ['WEB_PUBLIC_ORIGIN'].rstrip('/'),database_url=os.environ['DATABASE_URL'],encryption_key=os.environ['WEB_SESSION_ENCRYPTION_KEY'],api_token=os.environ['API_ACCESS_TOKEN'],cron_secret=os.environ['CRON_SECRET'])
        parsed=urlparse(obj.origin)
        if parsed.scheme!='https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username: raise ValueError('WEB_PUBLIC_ORIGIN must be an HTTPS origin')
        if not obj.database_url.startswith(('postgres://','postgresql://')): raise ValueError('Production identity requires PostgreSQL')
        if parse_qs(urlparse(obj.database_url).query).get('sslmode',[''])[0] not in ('require','verify-ca','verify-full'):
            raise ValueError('PostgreSQL requires TLS')
        if len(obj.cron_secret)<32 or obj.cron_secret==obj.api_token: raise ValueError('Use a dedicated CRON_SECRET of at least 32 characters')
        if len(obj.api_token)<32 or not obj.client_secret: raise ValueError('Missing server credentials')
        Fernet(obj.encryption_key.encode())
        return obj
