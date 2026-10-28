import time
import os
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet
import pytest
from app.identity.store import IdentityStore

@pytest.fixture(params=['sqlite'] + (['postgres'] if os.getenv('IDENTITY_TEST_DATABASE_URL') else []))
def store(tmp_path, request):
    url=os.environ['IDENTITY_TEST_DATABASE_URL'] if request.param=='postgres' else 'sqlite:///'+str(tmp_path/'identity.db')
    result=IdentityStore(url,Fernet.generate_key().decode())
    if request.param=='postgres':
        with result.connect() as db:
            for table in ('web_sessions','mcp_activity','identity_audit'): db.execute('DELETE FROM '+table)
            db.execute("UPDATE identity_policy SET group_id='' WHERE id=1")
    return result

def test_sessions_expire_and_encrypt_tokens(store):
    store.save_session('opaque', {'oid':'owner','access_token':'secret-graph-token'}, time.time()+10)
    assert store.get_session('opaque')['oid']=='owner'
    with store.connect() as db:
        row=db.execute('SELECT payload FROM web_sessions').fetchone()
        assert 'secret-graph-token' not in row['payload']
    store.save_session('expired',{'oid':'owner'},time.time()-1)
    assert store.get_session('expired') is None
    store.delete_session('opaque')
    assert store.get_session('opaque') is None

def test_policy_versions_change_and_invalid_group_rejected(store):
    assert store.get_policy()['group_id']==''
    before=store.get_policy()['version']
    group='12345678-1234-1234-1234-123456789abc'
    store.set_group(group,'owner')
    assert store.get_policy()['group_id']==group
    assert store.get_policy()['version']!=before
    with pytest.raises(ValueError): store.set_group('everyone','owner')

def test_concurrent_events_count_once_and_prune(store):
    now=time.time()
    def add(i): store.record_event(str(i),'claude','list_analyses',i%2==0,20,now)
    with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(add,range(40)))
    add(0)
    store.record_event('old','claude','list_analyses',True,1,now-31*86400)
    activity=store.activity(now)
    assert activity['clients'][0]['calls_30d']==40
    assert activity['clients'][0]['errors_30d']==20
    assert len(activity['recent'])==40
    assert store.prune(now)==1
