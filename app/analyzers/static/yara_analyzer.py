# app/analyzers/static/yara_analyzer.py
from ..yara_base import YaraAnalyzerBase


class YaraStaticAnalyzer(YaraAnalyzerBase):
    tool_section = 'static'
    target_kwarg = 'file_path'
