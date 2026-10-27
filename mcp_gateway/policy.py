"""Pure evidence policy shared with the legacy backend; no SDK imports."""
HIDDEN_KEYS = {
    'pcap_path', 'file_path', 'upload_path', 'results_path', 'payload', 'raw',
    'raw_data', 'raw_payload', 'hexdump', 'hex_dump', 'hex', 'ascii', 'body',
    'raw_hex', 'body_preview', 'payload_hex', 'payload_ascii',
    'request_body', 'response_body', 'authorization', 'cookie', 'set-cookie',
    'password', 'credentials', 'ntlm_response',
}


def page_value(value, pointer='', offset=0, limit=25):
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError('Invalid pagination')
    if len(pointer) > 1024 or (pointer and not pointer.startswith('/')):
        raise ValueError('Invalid JSON pointer')
    if pointer:
        for segment in pointer[1:].split('/'):
            key = segment.replace('~1', '/').replace('~0', '~')
            if key.lower() in HIDDEN_KEYS:
                raise ValueError('Sensitive fields are not exposed through MCP')
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif isinstance(value, list) and key.isdecimal() and int(key) < len(value):
                value = value[int(key)]
            else:
                raise ValueError('JSON pointer not found')
    if isinstance(value, list):
        total, page = len(value), value[offset:offset + limit]
    elif isinstance(value, dict):
        total = len(value)
        page = {key: value[key] for key in list(value)[offset:offset + limit]}
    else:
        total, page = 1, value
    return {
        'pointer': pointer, 'offset': offset, 'limit': limit, 'total': total,
        'next_offset': offset + limit if offset + limit < total else None, 'data': page,
    }
