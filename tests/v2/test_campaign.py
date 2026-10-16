import json,sys
from pathlib import Path
from experiments.runners.campaign import run_cell
from experiments.release import make_release

def test_campaign_marks_unavailable_and_runs_real_subprocess(tmp_path):
    root=Path(__file__).resolve().parents[2]
    first=run_cell({'runner':'not_available','id':'x12'},tmp_path/'x12',root)
    assert first['status']=='not_run'
    second=run_cell({'runner':'crypto-microbenchmark','runs':5},tmp_path/'x05',root)
    assert second['status']=='ok'
    assert (tmp_path/'x05'/'crypto.csv').exists()
    (tmp_path/'summary.json').write_text(json.dumps({'x05':'ok','x12':'not_run'}))
    archive=tmp_path.parent/'release-test.tar.gz'
    meta=make_release(tmp_path,archive)
    assert meta['status']=='ok' and meta['files']>=5
