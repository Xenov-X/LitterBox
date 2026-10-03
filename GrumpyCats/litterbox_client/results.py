"""Read saved analysis results.

Per-tool getters (file_info / static / dynamic / holygrail / risk) plus
`get_results` which is the legacy multi-purpose handle that backs the
`results --type` CLI.
"""

from typing import Dict


class ResultsMixin:
    def get_results(self, target: str, analysis_type: str) -> Dict:
        """Get saved results for a specific analysis type."""
        self._validate_analysis_type(analysis_type, ["static", "dynamic", "info"])
        target = self._validate_target(target)
        response = self._make_request("GET", f"/api/results/{analysis_type}/{target}")
        return response.json()

    def get_file_info(self, target: str) -> Dict:
        """File metadata: type, size, hashes, entropy, PE structure, etc."""
        target = self._validate_target(target)
        response = self._make_request("GET", f"/api/results/info/{target}")
        return response.json()

    def get_static_results(self, target: str) -> Dict:
        """Static analysis output (YARA / CheckPlz / Stringnalyzer)."""
        target = self._validate_target(target)
        response = self._make_request("GET", f"/api/results/static/{target}")
        return response.json()

    def get_dynamic_results(self, target: str) -> Dict:
        """Dynamic analysis output (memory scanners + behavioral telemetry)."""
        target = self._validate_target(target)
        response = self._make_request("GET", f"/api/results/dynamic/{target}")
        return response.json()

    def get_holygrail_results(self, target: str) -> Dict:
        """HolyGrail BYOVD output for a driver."""
        file_hash = self._validate_hash(target)
        response = self._make_request("GET", f"/api/results/holygrail/{file_hash}")
        return response.json()

    def get_risk_assessment(self, target: str) -> Dict:
        """Computed detection assessment: score, level, triggering indicators."""
        target = self._validate_target(target)
        response = self._make_request("GET", f"/api/results/risk/{target}")
        return response.json()
