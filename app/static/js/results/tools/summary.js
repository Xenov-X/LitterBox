// app/static/js/results/tools/summary.js
//
// Special "tool" — populates the top-of-page Summary tab (target details,
// total detections, scanner table, scan duration, payload output hand-off).
//
// Receives the full data.results object, not a single tool's results.

import { panel, kvGrid, summaryRow, escapeHtml, scanFailed, monetaDetectionCount } from './_shared.js';

// Row state for a scanner result: 'failed' when the scan produced no
// verdict (or exited non-zero with nothing parsed), otherwise undefined.
function rowState(result, count) {
    if (scanFailed(result)) return 'failed';
    if (result && result.status === 'failed' && !count) return 'failed';
    return undefined;
}

function failureDetail(result) {
    return result.error || result.reason ||
        (result.status === 'failed' ? 'Scanner exited non-zero; no findings parsed' : `Scan ${result.status}`);
}

export default {
    id: 'summary',
    // The summary renderer writes to several IDs (targetDetails, overallStatus,
    // totalDetections, scannerResultsBody, scanDuration). It doesn't have a
    // single root container, so we point elementId at scannerResultsBody — the
    // table body it always populates — to satisfy the registry's null check.
    elementId: 'scannerResultsBody',
    statsElementId: 'scannerResultsBody',

    render(results, ctx) {
        // Early-termination / whole-run failure case
        if (results.status === 'early_termination' || results.status === 'error') {
            const isEarly = results.status === 'early_termination';
            const headline = isEarly ? 'Process terminated before analysis could complete' : 'Analysis failed';
            const totalEl = document.getElementById('totalDetections');
            const overEl  = document.getElementById('overallStatus');
            if (totalEl) totalEl.textContent = '-';
            if (overEl)  { overEl.textContent = 'Analysis Failed'; overEl.style.color = 'var(--lb-accent)'; }

            if (ctx.statsElement) {
                ctx.statsElement.innerHTML = `
                    <tr>
                        <td colspan="4" style="padding: 16px; text-align: center;">
                            <div class="lb-strong" style="color: var(--lb-accent); margin-bottom: 4px;">${escapeHtml(headline)}</div>
                            <div class="lb-muted" style="font-size: 12px;">${escapeHtml(results.error || (isEarly ? 'Process terminated early' : 'Analysis failed'))}${
                                results.analysis_metadata?.total_duration
                                    ? ` (terminated after ${results.analysis_metadata.total_duration}s)`
                                    : ''
                            }</div>
                        </td>
                    </tr>`;
            }

            const targetEl = document.getElementById('targetDetails');
            if (targetEl) {
                targetEl.innerHTML = `
                    <div class="lb-empty threats" style="flex-direction: column; align-items: flex-start; padding: 12px 16px;">
                        <div class="lb-strong">Analysis Failed</div>
                        <div class="lb-muted" style="font-size: 12px;">${escapeHtml(headline)}. No results available.</div>
                    </div>`;
            }
            return;
        }

        // Target details
        const targetEl = document.getElementById('targetDetails');
        if (targetEl) {
            if (results.moneta?.findings?.process_info) {
                const info = results.moneta.findings.process_info;
                targetEl.innerHTML = panel('Target Process', kvGrid([
                    ['Name', info.name],
                    ['PID',  info.pid],
                    ['Path', info.path],
                ], 1));
            } else {
                const filePath = results.checkplz?.findings?.scan_results?.file_path || 'No file path available';
                targetEl.innerHTML = panel('Target File', `
                    <div class="lb-mono lb-strong" style="font-size: 13px; word-break: break-all;">${escapeHtml(filePath)}</div>
                `);
            }
        }

        // Build scanner table rows
        let totalDetections = 0;
        let incomplete = false;
        const rows = [];
        const push = (result, row) => {
            const state = rowState(result, row.count);
            if (state === 'failed') {
                incomplete = true;
                rows.push(summaryRow({ ...row, state, detail: failureDetail(result) }));
            } else {
                rows.push(summaryRow(row));
            }
        };

        if (results.yara) {
            const matches = Array.isArray(results.yara.matches) ? results.yara.matches : [];
            totalDetections += matches.length;
            push(results.yara, {
                name: 'YARA',
                triggered: matches.length > 0,
                count: matches.length,
                detail: matches.length > 0 ? `${matches.length} rule match${matches.length === 1 ? '' : 'es'}` : 'No rules matched',
            });
        }

        if (results.pe_sieve) {
            const susp = results.pe_sieve.findings?.total_suspicious || 0;
            totalDetections += susp;
            push(results.pe_sieve, {
                name: 'PE-sieve',
                triggered: susp > 0,
                count: susp,
                detail: susp > 0 ? `${susp} memory modification${susp === 1 ? '' : 's'} observed` : 'No memory modifications observed',
            });
        }

        if (results.moneta) {
            const f = results.moneta.findings || {};
            const susp = monetaDetectionCount(f);
            const isClean = susp === 0;
            totalDetections += susp;
            push(results.moneta, {
                name: 'Moneta',
                triggered: !isClean,
                count: susp,
                detail: isClean ? 'No anomalies observed' : 'Memory anomalies observed',
            });
        }

        if (results.checkplz) {
            const f = results.checkplz.findings || {};
            const hasDetection = !!f.scan_results?.detection_offset;
            if (hasDetection) totalDetections++;
            push(results.checkplz, {
                name: 'CheckPlz',
                triggered: hasDetection,
                count: hasDetection ? 1 : 0,
                detail: hasDetection ? (f.initial_threat || 'Signature triggered') : 'No signatures triggered',
            });
        }

        if (results.patriot) {
            const total = results.patriot.findings?.findings?.length || 0;
            totalDetections += total;
            push(results.patriot, {
                name: 'Patriot',
                triggered: total > 0,
                count: total,
                detail: total > 0 ? `${total} indicator${total === 1 ? '' : 's'} observed` : 'No indicators observed',
            });
        }

        if (results.hsb) {
            const total = results.hsb.findings?.summary?.total_findings || 0;
            totalDetections += total;
            push(results.hsb, {
                name: 'Hunt-Sleeping-Beacons',
                triggered: total > 0,
                count: total,
                detail: total > 0 ? 'Sleep-pattern indicators observed' : 'No sleep-pattern indicators',
            });
        }

        if (results.edr) {
            const r = results.edr;
            const summary = r.summary || {};
            const totalAlerts = summary.total_alerts != null
                ? summary.total_alerts
                : (Array.isArray(r.alerts) ? r.alerts.length : 0);
            const killedByEdr = !!(r.execution && r.execution.killed_by_edr);
            totalDetections += totalAlerts;
            const status = r.status || 'unknown';
            const isPolling = status === 'polling_alerts';
            const isTerminal = !isPolling;

            // Detail string — describes the row state for the operator.
            // The DETECTED badge below is driven *only* by alert count,
            // and only after the run is terminal: a scan in progress
            // shouldn't claim a verdict, and signals like killed_by_edr
            // / blocked_by_av without alert evidence are heuristics that
            // can fire on self-inflicted crashes.
            let detail;
            if (status === 'agent_unreachable')         detail = 'Agent unreachable';
            else if (status === 'busy')                 detail = 'Agent busy with another run';
            else if (status === 'partial')              detail = 'Run completed but alert query failed';
            else if (status === 'error')                detail = `Error: ${r.error || 'unknown'}`;
            else if (isPolling && summary.blocked_by_av) detail = 'EDR blocked spawn — correlating alerts…';
            else if (isPolling && killedByEdr)          detail = 'Killed by EDR — correlating alerts…';
            else if (isPolling)                         detail = 'Exec finished — correlating alerts…';
            else if (status === 'blocked_by_av' && totalAlerts > 0) detail = `Blocked by EDR · ${totalAlerts} alert${totalAlerts === 1 ? '' : 's'} raised`;
            else if (status === 'blocked_by_av')        detail = 'Blocked by EDR before execution';
            else if (killedByEdr && totalAlerts > 0)    detail = `Killed by EDR · ${totalAlerts} alert${totalAlerts === 1 ? '' : 's'} raised`;
            else if (killedByEdr)                       detail = 'Process exited non-zero — no correlating alerts';
            else if (totalAlerts > 0)                   detail = `${totalAlerts} alert${totalAlerts === 1 ? '' : 's'} raised`;
            else if (r.coverage === 'not_configured')   detail = 'Executed — no detection backend configured';
            else if (status === 'executed')              detail = 'Execution complete';
            else                                        detail = 'No alerts raised';

            // Statuses where the payload never ran (or alerts were never
            // queried) carry no verdict — never render them as Clean.
            const NO_VERDICT = new Set(['agent_unreachable', 'busy', 'error']);
            let state;
            if (isPolling) state = 'pending';
            else if (NO_VERDICT.has(status) || (status === 'partial' && totalAlerts === 0)) state = 'failed';
            if (state === 'failed') incomplete = true;

            rows.push(summaryRow({
                name: r.display_name || r.profile || 'EDR',
                triggered: isTerminal && totalAlerts > 0,
                count: totalAlerts,
                detail,
                state,
            }));
        }

        // Update summary stats. EDR runs that are still in their Phase-2
        // poll window haven't finished correlating yet — show that
        // explicitly instead of a misleading "Clean" green when the
        // count happens to be 0.
        const edrPolling = !!(results.edr && results.edr.status === 'polling_alerts');
        const totalEl = document.getElementById('totalDetections');
        const overEl  = document.getElementById('overallStatus');
        if (totalEl) totalEl.textContent = totalDetections;
        if (overEl) {
            if (edrPolling && totalDetections === 0) {
                overEl.textContent = 'Correlating…';
                overEl.style.color = 'var(--lb-accent-soft)';
            } else if (incomplete && totalDetections === 0) {
                // At least one scanner produced no verdict: "Clean" would
                // claim more than the run actually showed.
                overEl.textContent = 'Incomplete';
                overEl.style.color = 'var(--lb-sev-medium)';
            } else {
                overEl.textContent = totalDetections > 0 ? 'Detections' : 'Clean';
                overEl.style.color = totalDetections > 0 ? 'var(--lb-accent)' : 'var(--lb-sev-low)';
            }
        }

        // Set table content
        if (ctx.statsElement) {
            ctx.statsElement.innerHTML = rows.join('');
        }

        // Mirror scan duration
        const durEl = document.getElementById('scanDuration');
        const timerEl = document.getElementById('analysisTimer');
        if (durEl && timerEl) durEl.textContent = timerEl.textContent;

        // Process Output panel — populated for both dynamic runs (which
        // ship `process_output`) and EDR runs (which carry stdout/stderr
        // under `edr.execution`). The EDR side is synthesized so the same
        // PayloadManager logic renders both.
        if (results.process_output) {
            window.updatePayloadOutput?.(results);
        } else if (results.edr && results.edr.execution &&
                   (results.edr.execution.stdout || results.edr.execution.stderr)) {
            const e = results.edr.execution;
            window.updatePayloadOutput?.({
                process_output: {
                    stdout: e.stdout || '',
                    stderr: e.stderr || '',
                    had_output: !!(e.stdout || e.stderr),
                    output_truncated: false,
                },
            });
        }
    },
};
