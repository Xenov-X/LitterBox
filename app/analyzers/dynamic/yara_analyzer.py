# app/analyzers/dynamic/yara_analyzer.py
from ..yara_base import YaraAnalyzerBase


class YaraDynamicAnalyzer(YaraAnalyzerBase):
    tool_section = 'dynamic'
    target_kwarg = 'pid'

    def _scan_target_label(self, target):
        return f"PID: {target}"
