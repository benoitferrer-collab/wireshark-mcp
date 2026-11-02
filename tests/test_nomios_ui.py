from pathlib import Path

def test_nomios_preserves_analysis_modules_and_adds_identity_panels():
    html=Path('templates/index.html').read_text()
    assert 'Nomios PcapAnalyzer' in html
    assert 'id="nomiosAssistants"' in html
    assert 'id="nomiosAdmin"' in html
    for module in ['overview','dns','http','team-ia','timeline','streams','multi-pcap','packets','tls-audit','threat-intel','flow-behavior','lateral-movement','qos','tcp-health','playbook']:
        assert f'id="tab-{module}"' in html
        assert f'data-tab="{module}"' in html
    assert 'id="uploadArea"' in html and 'id="historyTable"' in html
    assert '/static/css/nomios.css' in html
