"""Hypothesis is an optional test dependency, never a silent security assertion."""
import os
import pytest
hypothesis=pytest.importorskip('hypothesis', reason='install project[test] to execute property testing')
from hypothesis import settings,HealthCheck
settings.register_profile('ci',max_examples=200,deadline=None,suppress_health_check=(HealthCheck.too_slow,))
settings.register_profile('nightly',max_examples=10000,deadline=None,suppress_health_check=(HealthCheck.too_slow,))
settings.load_profile(os.getenv('HYPOTHESIS_PROFILE','ci'))
