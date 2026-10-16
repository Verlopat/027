from baselines.journald_fss.driver import baseline as journald
from baselines.transparency_log.driver import baseline as tessera

def test_unavailable_external_baseline_never_fabricates_measurements():
    for adapter in (journald(),tessera()):
        assert adapter.verify().status=='not_run'
        assert adapter.cost()['gas'] is None
