from pathlib import Path
from pabla.experiments import Options,integrity,continuity,overhead,tradeoff,recovery,residual,stability,run_all
from pabla.analysis import aggregate,mcnemar_p,exact_ci,holm,bootstrap_median_ci

def test_experiments_local(tmp_path):
    o=Options(trials=1,event_count=12,batch_size=6)
    (tmp_path / "results" / "raw").mkdir(parents=True)
    (tmp_path / "results" / "derived").mkdir(parents=True)
    suite=run_all(tmp_path,o)
    derived=aggregate(suite,tmp_path)
    assert len(suite)==7 and derived["detection"]
    assert (tmp_path / "results" / "derived" / "summary.json").exists()
    assert integrity(o)
    assert continuity(o)
    assert overhead(o)
    assert tradeoff(o)
    r=recovery(o)
    assert r[0]['late_submission_rejected']==1
    assert r[0]['new_epoch_accepted']==1
    assert r[0]['historical_anchor_still_valid']==1
    res=residual(o)
    assert any(x['attack']=='AT9' and x['verdict']=='ACCEPT' for x in res)
    assert stability(o)

def test_stats():
    assert exact_ci(0,10)[0]==0
    assert exact_ci(10,10)[1]==1
    assert mcnemar_p([1,0,1],[0,0,1])==1.0
    assert holm([.01,.02,.03])==[.03,.04,.04] or all(x>=y for x,y in zip(holm([.01,.02,.03]),[.01,.02,.03]))
    lo,hi=bootstrap_median_ci([1,2,3,4],repetitions=200)
    assert lo<=hi
