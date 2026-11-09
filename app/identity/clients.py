"""Public brand attribution for known OAuth clients, never inferred from prompts."""
import json
import os
import re
PROVIDERS={'claude','chatgpt','litellm','generic'}
DEFAULTS={'34a342ef-6924-42f4-b3b5-c8e53da5bbd2':{'provider':'claude','name':'Claude'},
          'e9a0cf68-54c6-43cd-858f-018f9edfeea6':{'provider':'litellm','name':'LiteLLM'}}
def client_registry(environ=None):
    env=os.environ if environ is None else environ
    registry={key:dict(value) for key,value in DEFAULTS.items()}
    try:configured=json.loads(env.get('MCP_CLIENT_BRANDING','{}'))
    except (ValueError,TypeError):return registry
    if not isinstance(configured,dict):return registry
    for key,value in list(configured.items())[:50]:
        if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',key) or not isinstance(value,dict):continue
        provider=value.get('provider')
        if provider not in PROVIDERS:continue
        name=value.get('name')
        if not isinstance(name,str) or not 1<=len(name.strip())<=60:continue
        registry[key.lower()]={'provider':provider,'name':name.strip()}
    return registry
