# app/analyzers/yara_base.py
"""Shared YARA wrapper for the static (file) and dynamic (PID) scanners.

Output parsed here is `yara -s -m <rules> <target>`:

    RuleName [author="x",score=75] C:\\path\\to\\sample.exe
    0x3e8:$a1: matched data
    0x400:$hex: 4D 5A 90
    OtherRule [] C:\\path\\to\\sample.exe

A rule without a `meta:` section prints an empty `[]`. String lines are
`<offset>:<identifier>: <data>` (`<offset>:<length>:<identifier>: <data>`
when -L is passed).
"""
import logging
import os
import re
import threading

from .base import BaseSubprocessAnalyzer

logger = logging.getLogger(__name__)

_STRING_LINE = re.compile(r'^(0x[0-9a-fA-F]+):(?:(\d+):)?(\$[\w*]*):\s?(.*)$')
_HEADER_WITH_META = re.compile(r'^([A-Za-z_]\w*)\s+\[(.*)\]\s+(\S.*)$')
_HEADER_PLAIN = re.compile(r'^([A-Za-z_]\w*)\s+(\S.*)$')
_HEADER_MATCHED = re.compile(r'^([A-Za-z_]\w*) matched (.+)$')
_META_PAIR = re.compile(r'([A-Za-z_]\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+)|(true|false))')
_RULE_DECL = re.compile(rb'^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_]\w*)', re.M)
_RULE_STRING_DEF = re.compile(r'^\$([A-Za-z0-9_]*)\s*=\s*(.+)$')

_NOISE_LINES = {'YARA Scan Results', 'Static pattern matching analysis results.'}

# Metadata keys surfaced to the UI; `score` is normalised to `severity`.
_FIELD_MAPPINGS = {
    'date': 'creation_date',
    'modified': 'last_modified',
    'score': 'severity',
}
_IMPORTANT_FIELDS = {
    'id', 'creation_date', 'threat_name', 'severity',
    'description', 'author', 'date', 'modified', 'score',
}


class _RuleIndex:
    """{rule_name: (path, start, end)} over every .yar/.yara file under a
    rules directory, so a match can be traced back to its definition.

    Built once per directory and rebuilt only when a rule file is added,
    removed or modified. Offsets are byte offsets into the file, so a
    rule's source can be read without loading the (multi-MB) file whole.
    """

    _lock = threading.Lock()
    _cache = {}  # rules_dir -> (signature, index)

    @classmethod
    def get(cls, rules_dir):
        if not rules_dir or not os.path.isdir(rules_dir):
            return {}
        files = []
        for root, _dirs, names in os.walk(rules_dir):
            for name in names:
                if name.lower().endswith(('.yar', '.yara')):
                    path = os.path.join(root, name)
                    try:
                        files.append((path, os.path.getmtime(path)))
                    except OSError:
                        continue
        signature = tuple(sorted(files))
        with cls._lock:
            cached = cls._cache.get(rules_dir)
            if cached and cached[0] == signature:
                return cached[1]
        index = {}
        for path, _mtime in signature:
            try:
                with open(path, 'rb') as f:
                    data = f.read()
            except OSError:
                continue
            decls = list(_RULE_DECL.finditer(data))
            for i, m in enumerate(decls):
                end = decls[i + 1].start() if i + 1 < len(decls) else len(data)
                index.setdefault(m.group(1).decode('ascii'), (path, m.start(), end))
        with cls._lock:
            cls._cache[rules_dir] = (signature, index)
        return index


def _read_rule_strings(location):
    """Return {identifier: definition} for the rule at `location`."""
    path, start, end = location
    try:
        with open(path, 'rb') as f:
            f.seek(start)
            source = f.read(end - start).decode('utf-8', errors='replace')
    except OSError:
        return {}
    strings = {}
    in_strings = False
    for raw in source.splitlines():
        line = raw.strip()
        if line.startswith('strings:'):
            in_strings = True
            line = line[len('strings:'):].strip()
            if not line:
                continue
        elif line.startswith(('condition:', 'meta:')):
            in_strings = False
            continue
        if in_strings:
            m = _RULE_STRING_DEF.match(line)
            if m:
                strings[m.group(1)] = re.sub(r'\s+//.*$', '', m.group(2).strip())
    return strings


def parse_metadata(metadata_str):
    """Parse the `[k=v,...]` block yara prints with -m."""
    metadata = {}
    for key, quoted, number, boolean in _META_PAIR.findall(metadata_str or ''):
        if number:
            value = int(number)
        elif boolean:
            value = boolean == 'true'
        else:
            value = quoted.replace('\\"', '"').replace('\\\\', '\\')
        normalized_key = _FIELD_MAPPINGS.get(key, key)
        if normalized_key == 'severity' and isinstance(value, str):
            # Keep string severities ("high", "critical") — the risk
            # scorer maps them; coercing to 0 used to bucket them MEDIUM.
            value = int(value) if value.strip().lstrip('-').isdigit() else value.strip()
        if key in _IMPORTANT_FIELDS or normalized_key in _IMPORTANT_FIELDS:
            metadata[normalized_key] = value
            if key != normalized_key:
                metadata[key] = value
    return metadata


def parse_yara_output(output):
    """Parse `yara -s -m` stdout into a list of match dicts."""
    matches = []
    current = None
    for raw in (output or '').split('\n'):
        line = raw.strip()
        if not line or line in _NOISE_LINES or line.startswith('YARA Scan Results'):
            continue

        # String lines first: their data can contain '[x=' or ' matched '.
        sm = _STRING_LINE.match(line)
        if sm:
            if current is not None:
                current['strings'].append({
                    'offset': sm.group(1),
                    'identifier': sm.group(3),
                    'data': sm.group(4),
                })
            continue

        hm = _HEADER_MATCHED.match(line)
        if hm:
            rule, metadata_str, target = hm.group(1), '', hm.group(2)
        else:
            hm = _HEADER_WITH_META.match(line) or _HEADER_PLAIN.match(line)
            if not hm:
                logger.debug("Unrecognised yara output line: %r", line)
                continue
            if hm.re is _HEADER_WITH_META:
                rule, metadata_str, target = hm.group(1), hm.group(2), hm.group(3)
            else:
                rule, metadata_str, target = hm.group(1), '', hm.group(2)

        current = {
            'rule': rule,
            'metadata': parse_metadata(metadata_str),
            'strings': [],
            'target_file': target.strip(),
        }
        matches.append(current)
    return matches


class YaraAnalyzerBase(BaseSubprocessAnalyzer):
    """Subclasses set `tool_section` and `target_kwarg`."""

    tool_name = 'yara'
    extra_format_kwargs = ('rules_path',)

    def _rules_dir(self):
        rules_path = self.config['analysis'][self.tool_section]['yara']['rules_path']
        return os.path.dirname(os.path.abspath(rules_path))

    def _scan_target_label(self, target):
        return target

    def _parse_output(self, stdout):
        return parse_yara_output(stdout)

    def _postprocess_findings(self, findings):
        index = _RuleIndex.get(self._rules_dir())
        strings_cache = {}
        for match in findings:
            location = index.get(match['rule'])
            match['metadata']['rule_filepath'] = location[0] if location else None
            if not location:
                continue
            if match['rule'] not in strings_cache:
                strings_cache[match['rule']] = _read_rule_strings(location)
            rule_strings = strings_cache[match['rule']]
            for string in match['strings']:
                definition = rule_strings.get(string['identifier'].lstrip('$'))
                if definition is not None:
                    string['definition'] = definition
        return findings

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        return {
            'status': 'completed' if returncode == 0 else 'failed',
            'scan_info': {
                'target': self._scan_target_label(target),
                'rules_file': self.config['analysis'][self.tool_section]['yara']['rules_path'],
            },
            'matches': findings,
            'errors': stderr if stderr else None,
        }
