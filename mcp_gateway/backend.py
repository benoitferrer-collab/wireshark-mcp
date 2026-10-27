"""Bounded, sanitized evidence and authenticated access to the fixed backend."""
import json
import httpx
from .policy import HIDDEN_KEYS


def bounded_result(data: dict, source=None, task_id=None) -> dict:
    notices = []

    def notice(path, reason):
        if len(notices) < 40:
            notices.append(f'{path}: {reason}')

    def clean(value, path='$', depth=0):
        if depth > 8:
            notice(path, 'depth limit; query a narrower JSON pointer')
            return None
        if isinstance(value, dict):
            result = {}
            for index, (key, child) in enumerate(value.items()):
                if index >= 40:
                    notice(path, 'object limited to 40 keys; query a narrower pointer')
                    break
                if str(key).lower() in HIDDEN_KEYS:
                    notice(f'{path}.{key}', 'sensitive/raw field omitted')
                    continue
                result[key] = clean(child, f'{path}.{key}', depth + 1)
            return result
        if isinstance(value, list):
            if len(value) > 25:
                notice(path, f'first 25 of {len(value)} items; use pointer and pagination')
            return [clean(child, f'{path}/{i}', depth + 1) for i, child in enumerate(value[:25])]
        if isinstance(value, str) and len(value) > 1500:
            notice(path, 'string truncated to 1500 characters')
            return value[:1500]
        return value

    result = {'data': clean(data), 'limitations': notices}
    if source:
        result['source'] = source
    if task_id:
        result['task_id'] = task_id
    if len(json.dumps(result, ensure_ascii=True, default=str)) > 60000:
        result = {'data': None, 'source': source, 'task_id': task_id, 'limitations': [
            'Response exceeds 60000 JSON characters. Query a narrower pointer or lower limit.',
        ]}
    return result


class BackendClient:
    def __init__(self, settings, client=None):
        self.settings = settings
        self.client = client

    async def get(self, path: str, params=None):
        if not path.startswith('/api/') or '..' in path or '?' in path or '#' in path:
            raise ValueError('Invalid backend route')

        async def request(client):
            try:
                response = await client.get(
                    self.settings.backend_url + path, params=params,
                    headers={'Authorization': 'Bearer ' + self.settings.backend_token},
                    timeout=httpx.Timeout(90, connect=5), follow_redirects=False,
                )
                if response.status_code != 200:
                    raise ValueError(f'Analysis service returned HTTP {response.status_code}')
                return response.json()
            except (httpx.HTTPError, json.JSONDecodeError) as exc:
                raise ValueError('Analysis service unavailable or invalid response; retry in the application') from None

        if self.client is not None:
            return await request(self.client)
        async with httpx.AsyncClient() as client:
            return await request(client)
