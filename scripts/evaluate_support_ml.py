"""Offline Isolation Forest experiment. Never loads/publishes a deployed model or uploads data."""
import argparse
import json
import math
from pathlib import Path

FEATURES=('packets','bytes','rtt_samples','rtt_avg_ms','resets','retransmissions','zero_windows','duration_seconds','dns_error_responses')


def validate_dataset(records):
    if not isinstance(records,list) or len(records)>10000:
        raise ValueError('Provide at most 10000 adjudicated capture records')
    groups={'train':set(),'test':set()}
    seen=set()
    for row in records:
        if not isinstance(row,dict):raise ValueError('Invalid capture record')
        if row.get('label_status')!='adjudicated' or type(row.get('label')) is not int or row['label'] not in (0,1):
            raise ValueError('Human-adjudicated binary labels required; raw engineer votes are insufficient')
        if row.get('split') not in groups or not all(isinstance(row.get(k),str) and row[k] for k in ('capture_id','capture_signature','incident_id')):
            raise ValueError('Explicit train/test, capture signature and incident groups required')
        if row['capture_id'] in seen:raise ValueError('One record per capture; aggregate adjudicated votes first')
        seen.add(row['capture_id'])
        groups[row['split']].update(('capture:'+row['capture_id'],'signature:'+row['capture_signature'],'incident:'+row['incident_id']))
        if row['split']=='train' and row['label']!=0:
            raise ValueError('Novelty model trains on adjudicated normal captures only')
        values=row.get('features',{})
        if not isinstance(values,dict):raise ValueError('Numeric features object required')
        if row.get('coverage_complete') is not True:raise ValueError('Only complete inspected captures may enter this experiment')
        if row.get('synthetic_demo') is not False:raise ValueError('Explicitly exclude synthetic demonstrations from product evaluation')
        for key in FEATURES:
            value=values.get(key)
            if value is not None and (type(value) not in (float,int) or not math.isfinite(value) or value<0):
                raise ValueError('Invalid numeric feature')
    if groups['train'] & groups['test']:
        raise ValueError('Data leakage: capture, duplicate signature or incident shared across train/test')
    train=[row for row in records if row['split']=='train']
    test=[row for row in records if row['split']=='test']
    if len(train)<30 or len(test)<10 or {row['label'] for row in test}!={0,1}:
        raise ValueError('Need >=30 normal training captures and >=10 held-out captures including both labels')
    return train,test


def evaluate(records):
    train,test=validate_dataset(records)
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from importlib.metadata import version
    import numpy as np
    matrix=lambda rows:np.array([[row['features'].get(k) if row['features'].get(k) is not None else np.nan for k in FEATURES] for row in rows],dtype=float)
    imputer=SimpleImputer(strategy='median',keep_empty_features=True,add_indicator=True)
    x_train=imputer.fit_transform(matrix(train))
    x_test=imputer.transform(matrix(test))
    model=IsolationForest(n_estimators=100,random_state=42,contamination='auto',n_jobs=1)
    model.fit(x_train)
    predicted=(model.predict(x_test)==-1).astype(int).tolist()
    actual=[row['label'] for row in test]
    tp=sum(a==p==1 for a,p in zip(actual,predicted));fp=sum(a==0 and p==1 for a,p in zip(actual,predicted))
    fn=sum(a==1 and p==0 for a,p in zip(actual,predicted));tn=sum(a==p==0 for a,p in zip(actual,predicted))
    precision=tp/(tp+fp) if tp+fp else None
    recall=tp/(tp+fn) if tp+fn else None
    return {'experiment':'IsolationForest novelty detection','train_captures':len(train),'held_out_captures':len(test),
            'confusion':{'tp':tp,'fp':fp,'fn':fn,'tn':tn},'precision':precision,'recall':recall,
            'false_positive_rate':fp/(fp+tn) if fp+tn else None,'deployment_approved':False,
            'features':list(FEATURES),'seed':42,
            'library_versions':{name:version(name) for name in ('scikit-learn','numpy','scipy')},
            'limitations':['Expérience hors ligne ; aucun modèle n’est activé dans le produit.',
                           'Petits effectifs et domaine réseau peuvent rendre les résultats non représentatifs.',
                           'Détection statistique atypique, pas probabilité de panne ni classification de cause.',
                           'Choisir les critères métier et comparer aux règles existantes avant toute décision de déploiement.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset',type=Path)
    args=parser.parse_args()
    if args.dataset.stat().st_size>10*1024*1024:parser.error('Dataset exceeds 10MB')
    try:result=evaluate(json.loads(args.dataset.read_text()))
    except (ValueError,ImportError) as exc:parser.error(str(exc))
    print(json.dumps(result,indent=2,ensure_ascii=False,allow_nan=False))
