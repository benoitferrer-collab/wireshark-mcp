import json
import shutil
from pathlib import Path
import pytest
from app.tls.decoder import decode, safe_path

FIXTURES=Path(__file__).parent/'fixtures'/'tls'
TSHARK=shutil.which('tshark') or '/Applications/Wireshark.app/Contents/MacOS/tshark'
@pytest.mark.parametrize('stem,kind,secret',[('tls13','keylog','tls13.keys'),('rsa','rsa','rsa.key'),('http2','keylog','http2.keys')])
def test_public_capture_decrypts_without_payloads(tmp_path,stem,kind,secret):
    if not Path(TSHARK).exists() or not (FIXTURES/f'{stem}.pcap').exists():pytest.skip('Public fixtures / TShark unavailable')
    report=decode(FIXTURES/f'{stem}.pcap',kind,(FIXTURES/secret).read_bytes(),tmp_path,tshark=TSHARK)
    assert report['decrypted_packets']>0
    assert any(row['method']=='GET' for row in report['rows'])
    assert report['rows'][0]['packet_index']>=0
    assert not list(tmp_path.glob('secret*'))
    text=json.dumps(report)
    assert 'PRIVATE KEY' not in text and 'CLIENT_RANDOM' not in text
    assert all('?' not in row['path'] for row in report['rows'])

def test_wrong_key_is_an_honest_empty_result(tmp_path):
    if not Path(TSHARK).exists():pytest.skip('TShark unavailable')
    report=decode(FIXTURES/'tls13.pcap','keylog',b'CLIENT_RANDOM '+b'a'*64+b' '+b'b'*96+b'\n',tmp_path,tshark=TSHARK)
    assert report['decrypted_packets']==0
    assert report['state']=='no_match'

def test_paths_remove_credentials_queries_and_sensitive_segments():
    assert safe_path('https://user:pass@example.com/api?token=abc#secret')=='/api'
    assert safe_path('/reset/eyJhbGciOiJIUzI1NiJ9.longtoken.signature')=='/reset/[masqué]'
