"""OAuth resource server: tokens are issued by the configured external provider."""
import asyncio
import jwt
from mcp.server.auth.provider import AccessToken


class OAuthTokenVerifier:
    def __init__(self, settings, signing_key=None):
        self.settings = settings
        self.signing_key = signing_key
        self.jwks = jwt.PyJWKClient(settings.jwks_url, cache_keys=True, timeout=5)

    async def verify_token(self, token: str):
        try:
            key = self.signing_key
            if key is None:
                signing = await asyncio.to_thread(self.jwks.get_signing_key_from_jwt, token)
                key = signing.key
            claims = jwt.decode(
                token, key, algorithms=['RS256'], audience=self.settings.audience,
                issuer=self.settings.issuer,
                options={'require': ['exp', 'iat', 'sub', 'iss', 'aud']},
            )
            scopes = str(claims.get('scope', '')).split()
            if claims['sub'] not in self.settings.allowed_subjects or 'pcap:read' not in scopes:
                return None
            return AccessToken(
                token=token, client_id=claims.get('client_id') or claims.get('azp') or claims['sub'],
                scopes=scopes, expires_at=claims['exp'], resource=self.settings.public_url,
                subject=claims['sub'],
            )
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            return None
