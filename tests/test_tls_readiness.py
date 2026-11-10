from pathlib import Path
from app.tls.readiness import summarize, inspect_capture


def test_tls13_and_ephemeral_are_not_rsa_candidates():
    result=summarize([['8','0','0x0303','0x0304','0x1301'],['12','1','0x0303','','0xc02f']], 'rsa')
    assert result['rsa_candidates']==0
    assert result['keylog_required']==2
    assert result['state']=='keylog_recommended'
    assert result['sessions'][0]['frame_number']==8


def test_rsa_candidate_never_guarantees_key_matches():
    result=summarize([['8','0','0x0303','','0x009c']], 'rsa')
    assert result['rsa_candidates']==1
    assert result['state']=='rsa_candidate'
    assert 'correspondance' in result['message']


def test_missing_or_unknown_handshake_remains_unknown():
    assert summarize([], 'rsa')['state']=='unknown'
    result=summarize([['8','0','0x0303','','0xffff']], 'rsa')
    assert result['unknown']==1 and result['rsa_candidates']==0
    assert result['state']=='unknown'


def test_public_tls13_capture_needs_keylog():
    binary=Path('/Applications/Wireshark.app/Contents/MacOS/tshark')
    if not binary.exists():
        import pytest
        pytest.skip('TShark unavailable')
    result=inspect_capture(Path(__file__).parent/'fixtures/tls/tls13.pcap','rsa',tshark=str(binary))
    assert result['keylog_required']>0
    assert result['rsa_candidates']==0
