import pytest
from app.cloud.worker import poll_cycle

@pytest.mark.asyncio
async def test_normal_queue_failure_does_not_starve_tls_queue(monkeypatch):
    called=[]
    class Message:
        payload={'kind':'tls','task_id':'test'}
        metadata=type('M',(),{'delivery_count':1})()
    class Delivery:
        async def __aenter__(self):return Message()
        async def __aexit__(self,*args):return False
    class Queue:
        async def poll(self,topic,*args,**kwargs):
            called.append(topic)
            if topic=='pcap-analysis':raise RuntimeError('Normal queue unavailable')
            yield Delivery()
    def handle(*a):called.append('tls_handled');return True
    monkeypatch.setattr('app.tls.worker.handle_tls_delivery',handle)
    await poll_cycle(Queue(),object())
    assert called==['pcap-analysis','pcap-tls-decryption','tls_handled']
