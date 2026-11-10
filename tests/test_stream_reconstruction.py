from pathlib import Path
import importlib.util

def test_real_stream_payload_and_matching_session_metadata():
    spec=importlib.util.spec_from_file_location('real_stream_service',Path('app/services/stream_service.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    sessions=[{'src':'192.0.2.1:1','dst':'198.51.100.1:2','state':'WRONG','retransmissions':99},{'src':'192.0.2.10:42000','dst':'198.51.100.20:80','state':'CLOSED','retransmissions':2}]
    data=module.StreamService().reconstruct_tcp_stream(Path('app/demo_data/DEMO_Nomios_Support.pcap'),'192.0.2.10:42000:198.51.100.20:80',{'tcp_analysis':{'sessions':sessions}})
    assert 'GET /support/incident HTTP/1.1' in data['client_data']['raw']
    assert data['server_data']['size']==0
    assert data['state']=='CLOSED' and data['retransmissions']==2
    assert data['rst_count']==1
    assert data['packets'][3]['payload_size']==65

    binary=module.StreamService()._format_data_display(b"\x00"*8192,"client")
    assert binary["truncated"] is True and binary["displayed_bytes"]==4096
