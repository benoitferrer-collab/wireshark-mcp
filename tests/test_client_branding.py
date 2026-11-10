from app.identity.clients import client_registry
import json

def test_branding_only_accepts_explicit_providers_and_bounded_labels():
    mapping=client_registry({'MCP_CLIENT_BRANDING':json.dumps({'chatgpt-client':{'provider':'chatgpt','name':'ChatGPT Support'},'bad':{'provider':'https://tracker.invalid/icon','name':'Secret'},'huge':{'provider':'claude','name':'x'*61}})})
    assert mapping['chatgpt-client']['provider']=='chatgpt'
    assert 'bad' not in mapping and 'huge' not in mapping
    assert client_registry({'MCP_CLIENT_BRANDING':'oops'})
    assert client_registry({'MCP_CLIENT_BRANDING':'[]'})
