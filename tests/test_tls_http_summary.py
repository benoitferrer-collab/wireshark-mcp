from app.tls.http_summary import http_summary

def test_http_summary_counts_entire_report_not_only_display_page():
    rows=[]
    for n in range(40):
        rows.extend([{'frame_number':2*n+1,'method':'GET','host':'support.nomios.example','path':'/health','source':'192.0.2.10'},
                     {'frame_number':2*n+2,'status':503 if n==39 else 200,'path':'/health'}])
    result=http_summary({'rows':rows,'readiness':{'sessions':[{'version':'TLS 1.2'}],'observed_sessions':1}})
    assert result['methods']=={'GET':40}
    assert result['status_codes']=={'200':39,'503':1}
    assert result['hosts']==[{'name':'support.nomios.example','count':40}]
    assert result['total_requests']==40 and len(result['requests_sample'])==25
    assert result['tls_versions']=={'TLSv1.2':1}
    assert result['user_agents_available'] is False

def test_summary_does_not_export_unapproved_fields():
    result=http_summary({'rows':[{'method':'GET','path':'/safe','cookie':'secret','authorization':'secret','body':'secret'}]})
    import json
    assert 'secret' not in json.dumps(result)

def test_new_bounded_readiness_counts_are_explicitly_sampled():
    result=http_summary({'rows':[],'readiness':{'version_counts':{'TLS 1.3':100},'coverage':{'truncated':True,'packet_scan_limit':100000}}})
    assert result['tls_versions']=={'TLSv1.3':100}
    assert result['tls_versions_sampled'] is True
