"""Private queue-triggered HTTP consumer; no permanently reserved daemon memory.

This service has no public rewrite. Never mount it under the browser/MCP API.
The SDK owns callback transport, lease renewal, retries and acknowledgement.
"""
import asyncio
import logging
from fastapi import FastAPI, Request, HTTPException, Response
from vercel.queue import Message, RetryAfter, SanitizedName, accept_and_handle, subscribe
from .jobs import valid_id
from .objects import BlobObjects
from .worker import handle_delivery
from .context import ScratchMiddleware
from app.tls.worker import handle_tls_delivery

app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
app.add_middleware(ScratchMiddleware)
log=logging.getLogger(__name__)


async def dispatch(payload,count,topic):
    if topic not in ('pcap-analysis','pcap-tls-decryption'):raise ValueError('Unknown queue topic')
    task_id=valid_id(payload.get('task_id'))
    objects=BlobObjects()
    log.info('Queue processing topic=%s attempt=%s',topic,count)
    if topic=='pcap-tls-decryption':
        done=await asyncio.to_thread(handle_tls_delivery,task_id,count,objects)
    else:
        done=await asyncio.to_thread(handle_delivery,task_id,count,objects,timeout=250)
    if not done:raise RetryAfter(30)
    log.info('Queue completed topic=%s attempt=%s',topic,count)


# Manually configured container triggers assign the consumer group on Vercel.
# Keep the actual group for acknowledgements/lease renewals; never rewrite it.
_subscribers={}

def bind_subscriber(topic,group):
    if topic not in ('pcap-analysis','pcap-tls-decryption') or not group or len(group)>256:
        raise ValueError('Invalid queue metadata')
    key=(topic,group)
    if key in _subscribers:return
    if len(_subscribers)>=8:raise ValueError('Unexpected queue consumer groups')
    async def consume(message:Message[dict[str, object]]):
        await dispatch(message.payload,message.metadata.delivery_count,topic)
    _subscribers[key]=subscribe(topic=topic,consumer_group=SanitizedName(group))(consume)


@app.post('/{path:path}')
async def callback(request:Request,path:str):
    # Reject arbitrary JSON before SDK parsing. Header-only callbacks must fetch
    # their payload from Queues; inline callbacks are private platform delivery.
    if request.headers.get('ce-type')!='com.vercel.queue.v2beta':
        raise HTTPException(403,'Private queue callback required')
    body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>65536:raise HTTPException(413,'Queue callback too large')
    try:
        bind_subscriber(request.headers.get('ce-vqsqueuename'),request.headers.get('ce-vqsconsumergroup'))
        await accept_and_handle(bytes(body),request.headers,lease_duration=280)
    except RetryAfter:raise
    except Exception as exc:
        # No body, headers, tokens, secret material or exception messages logged.
        log.warning('Queue callback failed type=%s',type(exc).__name__)
        raise HTTPException(503,'Queue delivery not completed') from None
    return Response(status_code=204)
