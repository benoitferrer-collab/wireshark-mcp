import pytest
from vercel.queue import RetryAfter
from fastapi.testclient import TestClient
from app.cloud.on_demand import app, dispatch


def test_untrusted_callback_cannot_start_analysis(monkeypatch):
    called=[]
    monkeypatch.setattr('app.cloud.on_demand.handle_delivery',lambda *a,**kw:called.append(a))
    response=TestClient(app).post('/',json={'task_id':'fake'})
    assert response.status_code in (400,401,403)
    assert not called


@pytest.mark.asyncio
async def test_dispatch_only_known_topic_and_id(monkeypatch):
    called=[]
    monkeypatch.setattr('app.cloud.on_demand.BlobObjects',lambda:object())
    monkeypatch.setattr('app.cloud.on_demand.handle_delivery',lambda *a,**kw:called.append((a,kw)) or True)
    await dispatch({'task_id':'safe'},1,'pcap-analysis')
    assert called[0][1]['timeout']==250
    with pytest.raises(ValueError):await dispatch({'task_id':'../bad'},1,'pcap-analysis')
    with pytest.raises(ValueError):await dispatch({'task_id':'safe'},1,'other')


@pytest.mark.asyncio
async def test_retry_is_not_acknowledged_as_success(monkeypatch):
    monkeypatch.setattr('app.cloud.on_demand.BlobObjects',lambda:object())
    monkeypatch.setattr('app.cloud.on_demand.handle_delivery',lambda *a,**kw:False)
    with pytest.raises(RetryAfter):
        await dispatch({'task_id':'safe'},1,'pcap-analysis')

@pytest.mark.asyncio
async def test_actual_sdk_dispatch_matches_platform_assigned_group(monkeypatch):
    from datetime import datetime,timezone
    from vercel.queue import Message,MessageMetadata,SanitizedName
    from vercel.queue._internal.subscribers import call_subscribers
    from app.cloud.on_demand import bind_subscriber
    called=[]
    monkeypatch.setattr('app.cloud.on_demand.dispatch',lambda *args: record(called,args))
    bind_subscriber('pcap-analysis','platform-consumer-test')
    message=Message(payload={'task_id':'safe'},metadata=MessageMetadata(message_id='message',delivery_count=2,
        created_at=datetime.now(timezone.utc),topic='pcap-analysis',consumer_group=SanitizedName('platform-consumer-test')))
    await call_subscribers(message)
    assert called==[({'task_id':'safe'},2,'pcap-analysis')]

async def record(called,args):called.append(args)

def test_real_sdk_accepts_v2_callback_and_acknowledges_after_dispatch(monkeypatch):
    from vercel.queue import QueueClient
    monkeypatch.setenv('VERCEL_REGION','iad1')
    called=[]
    async def work(payload,count,topic):called.append(('work',payload,count,topic))
    async def acknowledge(self,message):called.append(('ack',str(message.metadata.consumer_group)))
    monkeypatch.setattr('app.cloud.on_demand.dispatch',work)
    monkeypatch.setattr(QueueClient,'acknowledge',acknowledge)
    headers={'ce-type':'com.vercel.queue.v2beta','ce-vqsqueuename':'pcap-analysis',
        'ce-vqsconsumergroup':'sdk-callback-test','ce-vqsmessageid':'message',
        'ce-vqsreceipthandle':'receipt','ce-vqscreatedat':'2026-11-10T10:00:00Z',
        'ce-vqsregion':'iad1','ce-vqsdeliverycount':'2','content-type':'application/json'}
    response=TestClient(app).post('/',json={'task_id':'safe'},headers=headers)
    assert response.status_code==204,response.text
    assert called==[('work',{'task_id':'safe'},2,'pcap-analysis'),('ack','sdk-callback-test')]


def test_config_has_private_separate_v2_consumers_and_no_daemon():
    import json
    from pathlib import Path
    config=json.loads((Path(__file__).parents[1]/'vercel.json').read_text())
    assert not config.get('daemons')
    for name,topic in [('worker','pcap-analysis'),('tlsworker','pcap-tls-decryption')]:
        assert not any(r.get('destination',{}).get('service')==name for r in config['rewrites'])
        settings=config['services'][name]['functions']['**']
        assert settings['maxDuration']==300
        assert 'maxConcurrency' not in settings # no paid beta opt-in
        trigger=settings['experimentalTriggers'][0]
        assert trigger['type']=='queue/v2beta' and trigger['topic']==topic
        assert trigger['maxConcurrency']==1 and trigger['maxDeliveries']==3

def test_child_receives_request_oidc_without_persisting_it(monkeypatch):
    import os,sys
    from vercel.headers import HeadersContext
    from app.tls.worker import run_isolated
    # Child only tests presence/equality, never prints a token.
    code="import os,sys; sys.exit(0 if os.environ.get('VERCEL_OIDC_TOKEN')=='synthetic-test-token' else 2)"
    with HeadersContext({'x-vercel-oidc-token':'synthetic-test-token'}).use():
        result=run_isolated([sys.executable,'-c',code],timeout=3)
    assert result.returncode==0
    assert os.environ.get('VERCEL_OIDC_TOKEN')!='synthetic-test-token'
