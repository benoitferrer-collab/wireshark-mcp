import pytest
from scripts.evaluate_support_ml import validate_dataset


def dataset():
    return [{'capture_id':f'c{i}','capture_signature':f's{i}','incident_id':f'i{i}',
             'label_status':'adjudicated','coverage_complete':True,'synthetic_demo':False,'label':0 if i<35 else 1,
             'split':'train' if i<30 else 'test','features':{'packets':10+i}} for i in range(40)]


def test_requires_adjudicated_capture_disjoint_and_incident_disjoint_labels():
    rows=dataset()
    assert tuple(map(len,validate_dataset(rows)))==(30,10)
    rows[-1]['incident_id']=rows[0]['incident_id']
    with pytest.raises(ValueError,match='leakage'):validate_dataset(rows)
    rows=dataset();rows[-1]['capture_signature']=rows[0]['capture_signature']
    with pytest.raises(ValueError,match='leakage'):validate_dataset(rows)
    rows=dataset();rows[-1]['label_status']='unadjudicated_engineer_feedback'
    with pytest.raises(ValueError,match='adjudicated'):validate_dataset(rows)


def test_missing_sample_counts_and_nonfinite_or_string_features_rejected():
    with pytest.raises(ValueError):validate_dataset(dataset()[:20])
    for value in [float('nan'),-1,'192.0.2.1',True]:
        rows=dataset();rows[0]['features']['packets']=value
        with pytest.raises(ValueError):validate_dataset(rows)
