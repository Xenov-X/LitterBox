# app/utils/reporting.py
"""HTML report rendering."""
import datetime as dt

from flask import render_template

from .json_helpers import extract_detection_counts, format_size
from .risk_analyzer import _calculate_byovd_risk, calculate_risk, get_risk_level


# AV-killer trio — same set used by holygrail/core.js when highlighting
# critical imports. Surfaced here so the report's chip row can flag them.
_AV_KILLER_IMPORTS = {'ZwTerminateProcess', 'ZwOpenProcess', 'PsLookupProcessByProcessId'}


def _calculate_byovd_score(byovd_results):
    """BYOVD score + label for the report hero card.

    Uses the same scorer as the results/summary pages
    (risk_analyzer._calculate_byovd_risk) so the downloaded report can't
    disagree with the UI. Returns (None, None) without BYOVD findings.
    """
    if not byovd_results or not byovd_results.get('findings'):
        return None, None

    score, _factors = _calculate_byovd_risk(byovd_results)

    if score >= 70:
        label = 'High'
    elif score >= 40:
        label = 'Medium'
    else:
        label = 'Low'

    return score, label


def generate_html_report(file_info=None, static_results=None,
                         dynamic_results=None, byovd_results=None,
                         edr_results=None, pid=None):
    """Render the report.html template with risk + detection summary.

    `byovd_results` is the parsed contents of byovd_results.json from a
    HolyGrail driver scan; only populated when the analysed sample is a
    `.sys` driver and HolyGrail has been run. When set, the report swaps
    the hero risk card and the chip row for BYOVD-specific equivalents
    (HolyGrail score + LOLDrivers/Win10/Win11/critical-import chips) and
    promotes the BYOVD section above the File Information section.

    `edr_results` is a {profile_name: findings_dict} mapping populated when
    the file has been dispatched to one or more EDR profiles. When set,
    the report adds a per-profile EDR section listing the alerts raised
    and the execution output captured by the Whiskers agent.
    """
    is_process_analysis = pid is not None and not file_info
    analysis_type = 'process' if is_process_analysis else 'file'

    # EDR results are shown in their own section but, as on the results
    # page and summary (helpers.calculate_and_add_risk), they don't feed
    # the Detection Score — otherwise the report and UI disagree.
    risk_score, risk_factors = calculate_risk(
        analysis_type=analysis_type,
        file_info=file_info,
        static_results=static_results,
        dynamic_results=dynamic_results,
    )
    risk_level = get_risk_level(risk_score)

    detections = {}
    if static_results or dynamic_results:
        detections = extract_detection_counts(dynamic_results or static_results)

    if dynamic_results and is_process_analysis:
        if 'process_output' not in dynamic_results:
            dynamic_results['process_output'] = {
                'had_output': False,
                'output': '',
                'stdout': '',
                'stderr': '',
            }

    is_driver_report = byovd_results is not None and bool(byovd_results.get('findings'))
    byovd_score, byovd_label = _calculate_byovd_score(byovd_results)
    byovd_class = (byovd_label or 'low').lower()

    return render_template(
        "report.html",
        generated_on=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        is_process_analysis=is_process_analysis,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        detections=detections,
        file_info=file_info,
        static_results=static_results,
        dynamic_results=dynamic_results,
        byovd_results=byovd_results,
        edr_results=edr_results,
        is_driver_report=is_driver_report,
        byovd_score=byovd_score,
        byovd_label=byovd_label,
        byovd_class=byovd_class,
        av_killer_imports=_AV_KILLER_IMPORTS,
        pid=pid,
        format_size=format_size,
    )
