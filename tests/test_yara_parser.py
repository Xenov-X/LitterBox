# tests/test_yara_parser.py
from app.analyzers.yara_base import parse_metadata, parse_yara_output


def test_rule_without_meta_is_not_dropped():
    out = "CustomRule [] C:\\Uploads\\x.exe\n0x10:$a: hello\n"
    matches = parse_yara_output(out)
    assert [m['rule'] for m in matches] == ['CustomRule']
    assert matches[0]['metadata'] == {}
    assert matches[0]['strings'] == [{'offset': '0x10', 'identifier': '$a', 'data': 'hello'}]


def test_string_lines_attach_to_their_own_rule():
    out = (
        "First [score=80] t.exe\n"
        "0x1:$a: one\n"
        "Second [] t.exe\n"
        "0x2:$b: two\n"
    )
    first, second = parse_yara_output(out)
    assert [s['identifier'] for s in first['strings']] == ['$a']
    assert [s['identifier'] for s in second['strings']] == ['$b']


def test_string_data_with_colons_and_brackets():
    out = "R [] t.exe\n0x3e8:$a1: Error: bad [x=1] matched value\n"
    (m,) = parse_yara_output(out)
    assert m['strings'][0] == {'offset': '0x3e8', 'identifier': '$a1', 'data': 'Error: bad [x=1] matched value'}


def test_string_line_with_length_column():
    (m,) = parse_yara_output("R [] t.exe\n0x10:12:$mutex: Remcos_Mutex\n")
    assert m['strings'][0]['identifier'] == '$mutex'
    assert m['strings'][0]['data'] == 'Remcos_Mutex'


def test_pid_target_and_plain_header():
    (m,) = parse_yara_output("Rule_A 1234\n")
    assert m['rule'] == 'Rule_A' and m['target_file'] == '1234'


def test_metadata_types_and_quoting():
    meta = parse_metadata('author="a, b",score=75,description="say \\"hi\\"",threat_name="W.T.X",flag=true')
    assert meta['severity'] == 75 and meta['score'] == 75
    assert meta['author'] == 'a, b'
    assert meta['description'] == 'say "hi"'
    assert meta['threat_name'] == 'W.T.X'


def test_string_severity_is_kept():
    assert parse_metadata('severity="high"')['severity'] == 'high'
    assert parse_metadata('severity="90"')['severity'] == 90
