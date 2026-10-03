# app/analyzers/dynamic/pe_sieve_analyzer.py
from ..base import BaseSubprocessAnalyzer


class PESieveAnalyzer(BaseSubprocessAnalyzer):
    tool_section = 'dynamic'
    tool_name = 'pe_sieve'
    target_kwarg = 'pid'

    # Summary counters printed by pe-sieve; label -> findings key. Order
    # matters only for readability — each label is matched exactly.
    _SUMMARY_FIELDS = {
        'Total scanned': 'total_scanned',
        'Skipped': 'skipped',
        'Hooked': 'hooked',
        'Replaced': 'replaced',
        'Hdrs Modified': 'hdrs_modified',
        'IAT Hooks': 'iat_hooks',
        'Implanted': 'implanted',
        'Implanted PE': 'implanted_pe',
        'Implanted shc': 'implanted_shc',
        'Unreachable files': 'unreachable',
        'Other': 'other',
        'Total suspicious': 'total_suspicious',
    }

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        # pe-sieve's own returncode is unreliable. A run only counts as a
        # scan if its SUMMARY block was parsed: on failure (e.g. "Could not
        # open the process") it prints text but no counters, and reporting
        # that as "completed, 0 suspicious" reads as a clean result.
        if not findings.get('summary_parsed'):
            return {
                'status': 'error',
                'error': self._failure_reason(stdout) or 'PE-sieve produced no scan summary',
                'findings': findings,
                'errors': stderr if stderr else None,
            }
        return {
            'status': 'completed',
            'findings': findings,
            'errors': stderr if stderr else None,
        }

    @staticmethod
    def _failure_reason(stdout):
        for line in (stdout or '').splitlines():
            line = line.strip()
            if line.startswith('[-]') or 'could not' in line.lower() or 'failed' in line.lower():
                return line.lstrip('[-] ').strip()
        return None

    def _parse_output(self, output):
        findings = {key: 0 for key in self._SUMMARY_FIELDS.values()}
        findings['summary_parsed'] = False
        findings['raw_output'] = output

        for line in (output or '').split('\n'):
            label, sep, value = line.strip().partition(':')
            key = self._SUMMARY_FIELDS.get(label.strip())
            if not sep or key is None:
                continue
            try:
                findings[key] = int(value.strip())
            except ValueError:
                continue
            if key == 'total_scanned':
                findings['summary_parsed'] = True

        return findings
