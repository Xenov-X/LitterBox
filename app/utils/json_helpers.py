# app/utils/json_helpers.py
"""JSON I/O, formatting, and detection-count extraction helpers."""
import json
import os
import tempfile
import time

from .risk_analyzer import moneta_detection_count


def write_json_atomic(filepath, data, retries=5):
    """Write JSON so readers never see a partial file.

    Writes a sibling temp file and os.replace()s it over the target. On
    Windows the replace fails with PermissionError while another thread
    has the target open for reading; retry briefly before giving up.
    """
    directory = os.path.dirname(filepath) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix='.' + os.path.basename(filepath) + '.', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(retries):
            try:
                os.replace(tmp_path, filepath)
                return
            except PermissionError:
                if attempt == retries - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def load_json_file(filepath):
    """Safely load a JSON file. Returns None if missing or unreadable."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {filepath}: {str(e)}")
        return None


def format_hex(value):
    """Format a value as a lowercase hexadecimal string."""
    if isinstance(value, str) and value.startswith('0x'):
        return value.lower()
    try:
        return f"0x{int(value):x}"
    except (ValueError, TypeError):
        return str(value)


def format_size(size_bytes):
    """Format a byte count as a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def extract_detection_counts(results):
    """Extract per-analyzer detection counts from a results dict."""
    counts = {'yara': 0, 'pesieve': 0, 'moneta': 0, 'patriot': 0, 'hsb': 0}

    try:
        yara_matches = results.get('yara', {}).get('matches', [])
        counts['yara'] = (
            len({match.get('rule') for match in yara_matches if match.get('rule')})
            if isinstance(yara_matches, list) else 0
        )

        pesieve_findings = results.get('pe_sieve', {}).get('findings', {})
        counts['pesieve'] = int(pesieve_findings.get('total_suspicious', 0) or 0)

        counts['moneta'] = moneta_detection_count(results.get('moneta', {}).get('findings', {}))

        patriot_findings = results.get('patriot', {}).get('findings', {}).get('findings', [])
        counts['patriot'] = len(patriot_findings) if isinstance(patriot_findings, list) else 0

        hsb_findings = results.get('hsb', {}).get('findings', {})
        if hsb_findings and hsb_findings.get('detections'):
            counts['hsb'] = sum(
                len(detection.get('findings') or [])
                for detection in hsb_findings['detections']
            )

    except (TypeError, ValueError, IndexError):
        pass

    return counts


def cap_saved_stdio(edr_results: dict, cap: int = 256 * 1024) -> dict:
    """Truncate `execution.{stdout,stderr}` in saved EDR findings.

    Results saved before AgentClient capped output can hold hundreds of
    MB of stdout (mimikatz spamming its prompt 18M times), which hung
    the browser. Applied wherever saved EDR findings are served.
    Returns the dict, modified in place.
    """
    exec_blk = edr_results.get('execution') if isinstance(edr_results, dict) else None
    if not isinstance(exec_blk, dict):
        return edr_results
    for field in ('stdout', 'stderr'):
        value = exec_blk.get(field)
        if isinstance(value, str) and len(value.encode('utf-8', errors='replace')) > cap:
            raw = value.encode('utf-8', errors='replace')
            head = raw[:cap].decode('utf-8', errors='replace')
            exec_blk[field] = (
                f"{head}\n\n... [truncated by saved-view loader — "
                f"original was {len(raw):,} bytes, kept first {cap:,}]"
            )
    return edr_results
