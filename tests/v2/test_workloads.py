from pathlib import Path
import hashlib
import pytest
from experiments.workloads.loghub import verified_trace
from experiments.analysis.scheduling import compare,read_price_trace
from pabla.v2.scheduling import brute_optimum

def test_verified_real_trace_loader_refuses_wrong_checksum_and_preserves_bytes(tmp_path):
    p=tmp_path/'dataset.log';payload=b'2026-10-16T12:00:00Z first\n2026-10-16T12:00:01Z second\n'
    p.write_bytes(payload)
    with pytest.raises(ValueError):verified_trace('test',p,'0'*64,'fixture')
    t=verified_trace('test',p,hashlib.sha256(payload).hexdigest(),'fixture')
    xs=list(t.events());assert len(xs)==2 and xs[0][1]==payload.splitlines()[0]
    assert xs[1][0]-xs[0][0]==1000

def test_real_gas_price_trace_required(tmp_path):
    file=tmp_path/'prices.csv';file.write_text('price,source\n10,synthetic\n')
    with pytest.raises(ValueError):read_price_trace(file)
    file.write_text('price,source\n10,fixture-measured\n30,fixture-measured\n8,fixture-measured\n')
    values,digest=read_price_trace(file)
    assert values==[10,30,8] and len(digest)==64
    comparisons=compare(values,2)
    assert len(comparisons)==3 and all(x['ratio_to_optimum']>=1 for x in comparisons)
    assert comparisons[0]['cost_price_units']==brute_optimum(values,2)[0]
