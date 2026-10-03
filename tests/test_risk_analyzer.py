# tests/test_risk_analyzer.py
import pytest

from app.utils import json_helpers
from app.utils.risk_analyzer import (
    MONETA_DETECTION_KEYS,
    RiskCalculator,
    _calculate_hsb_risk,
    calculate_risk,
    moneta_detection_count,
)


def _match(severity):
    return {'rule': 'r', 'metadata': {'severity': severity}, 'strings': []}


@pytest.mark.parametrize('value,label', [
    (100, 'CRITICAL'), (90, 'CRITICAL'), (85, 'HIGH'), (75, 'HIGH'), (70, 'HIGH'),
    (65, 'MEDIUM'), (50, 'MEDIUM'), (20, 'LOW'), (5, 'INFO'),
    ('high', 'HIGH'), ('Critical', 'CRITICAL'), ('75', 'HIGH'), ('bogus', 'MEDIUM'),
])
def test_severity_buckets(value, label):
    assert RiskCalculator.severity_label(value) == label


def test_higher_score_never_ranks_lower():
    s90, _ = RiskCalculator.calculate_yara_risk([_match(90)])
    s80, _ = RiskCalculator.calculate_yara_risk([_match(80)])
    s75, _ = RiskCalculator.calculate_yara_risk([_match(75)])
    assert s90 >= s80 >= s75 > RiskCalculator.calculate_yara_risk([_match(50)])[0]


def _process_results(yara_severity):
    return {
        'yara': {'status': 'completed', 'matches': [_match(yara_severity), _match(yara_severity)]},
        'pe_sieve': {'status': 'completed', 'findings': {'total_suspicious': 3}},
        'moneta': {'status': 'completed', 'findings': {'total_private_rwx': 2, 'total_modified_code': 2}},
    }


def test_critical_yara_lifts_process_cap_like_high():
    crit, _ = calculate_risk('process', dynamic_results=_process_results(100))
    high, _ = calculate_risk('process', dynamic_results=_process_results(80))
    assert crit >= high > 75


def test_process_score_capped_without_high_signal():
    score, _ = calculate_risk('process', dynamic_results=_process_results(50))
    assert score <= 75


def _hsb(severity, count=1):
    return {'hsb': {'findings': {'detections': [{'findings': [{}] * count, 'max_severity': severity}]}}}


def test_hsb_severity_is_monotonic_and_labelled():
    scores = []
    for sev in (1, 2, 3, 4):
        factors = []
        score, high = _calculate_hsb_risk(_hsb(sev), 'process', factors)
        scores.append(score)
        assert high == (sev >= 3)
        assert ['LOW', 'MID', 'HIGH', 'CRITICAL'][sev - 1] in factors[0]
    assert scores == sorted(scores)


def test_patriot_level_is_scored():
    low, _ = calculate_risk('process', dynamic_results={'patriot': {'findings': {'findings': [{'level': 'LOW'}]}}})
    crit, _ = calculate_risk('process', dynamic_results={'patriot': {'findings': {'findings': [{'level': 'CRITICAL'}]}}})
    assert crit > low


def test_runtime_imports_do_not_score():
    imports = [{'function': 'loadlibrarya', 'is_runtime_import': True},
               {'function': 'getprocaddress', 'is_runtime_import': True}]
    score, factors = RiskCalculator.calculate_pe_risk({'suspicious_imports': imports})
    assert score == 0 and factors == []


def test_moneta_count_excludes_superset_and_informational():
    findings = {'total_private_rwx': 1, 'total_abnormal_private_exec': 1, 'total_unsigned_modules': 3,
                'total_regions': 40}
    assert moneta_detection_count(findings) == 1
    counts = json_helpers.extract_detection_counts({'moneta': {'findings': findings}})
    assert counts['moneta'] == 1


def test_moneta_keys_match_scoring_weights():
    # Every detection key contributes to the score.
    for key in MONETA_DETECTION_KEYS:
        score, _ = calculate_risk('process', dynamic_results={'moneta': {'findings': {key: 1}}})
        assert score > 0, key


def test_hsb_count_includes_all_detections():
    results = {'hsb': {'findings': {'detections': [{'findings': [{}, {}]}, {'findings': [{}]}]}}}
    assert json_helpers.extract_detection_counts(results)['hsb'] == 3
