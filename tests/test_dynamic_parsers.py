# tests/test_dynamic_parsers.py
from app.analyzers.dynamic.hsb_analyzer import HSBAnalyzer
from app.analyzers.dynamic.moneta_analyzer import MonetaAnalyzer
from app.analyzers.dynamic.pe_sieve_analyzer import PESieveAnalyzer

PE_SIEVE_OK = """PID: 1234
---
SUMMARY:

Total scanned:      45
Skipped:            0
-
Hooked:             1
Replaced:           0
Hdrs Modified:      0
IAT Hooks:          0
Implanted:          2
Implanted PE:       1
Implanted shc:      1
Unreachable files:  0
Other:              0
-
Total suspicious:   3
---
"""

PE_SIEVE_FAIL = "[-] Could not open the process Error: 5\n[!] Scanning the process failed\n"


def _run(analyzer_cls, stdout):
    a = analyzer_cls({})
    findings = a._parse_output(stdout)
    findings = a._postprocess_findings(findings)
    return a._build_envelope(findings, 0, '', stdout, 1234)


def test_pe_sieve_summary():
    r = _run(PESieveAnalyzer, PE_SIEVE_OK)
    assert r['status'] == 'completed'
    f = r['findings']
    assert (f['total_scanned'], f['hooked'], f['implanted'], f['implanted_pe'], f['total_suspicious']) == (45, 1, 2, 1, 3)


def test_pe_sieve_failure_is_not_clean():
    r = _run(PESieveAnalyzer, PE_SIEVE_FAIL)
    assert r['status'] == 'error'
    assert 'Could not open the process' in r['error']


MONETA_OK = """notepad.exe : 1234 : x64 : C:\\Windows\\System32\\notepad.exe
  0x00007FF600000000:0x00010000   | EXE Image           | C:\\Windows\\System32\\notepad.exe
    0x00000000001A0000:0x00001000 | RWX      | 0x00000000 | Abnormal private executable memory
... scan completed (0.512000 second duration)
"""

MONETA_FAIL = """... failed to grant SeDebug privilege to self. Certain processes will be inaccessible.
... failed to open handle to PID 1234
... scan completed (0.010000 second duration)
"""


def test_moneta_scan():
    r = _run(MonetaAnalyzer, MONETA_OK)
    assert r['status'] == 'completed'
    f = r['findings']
    assert f['process_info']['name'] == 'notepad.exe'
    assert f['total_private_rwx'] == 1 and f['total_abnormal_private_exec'] == 1
    assert f['detection_count'] == 1


def test_moneta_failure_is_not_clean():
    r = _run(MonetaAnalyzer, MONETA_FAIL)
    assert r['status'] == 'error'
    assert 'failed to open handle' in r['error']


def test_moneta_nonfatal_warning_is_ok():
    r = _run(MonetaAnalyzer, "... failed to grant SeDebug privilege to self.\n" + MONETA_OK)
    assert r['status'] == 'completed'


def test_hsb_none_severity_and_per_process_max():
    a = HSBAnalyzer({})
    a.pid = 1
    sections = {
        'summary': {},
        'detections': [
            {'findings': [{'severity': 'CRITICAL'}]},
            {'findings': [{'severity': None}, {'severity': 'MID'}]},
        ],
    }
    a._enrich_findings(sections)
    assert [d['max_severity'] for d in sections['detections']] == [4, 2]
    assert sections['summary']['max_severity'] == 4
    assert sections['summary']['severity_counts'] == {'CRITICAL': 1, 'HIGH': 0, 'MID': 1, 'LOW': 1}
