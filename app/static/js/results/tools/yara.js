// app/static/js/results/tools/yara.js
import { errorPanel, cleanState, statRow, panel, kvGrid, tag, escapeHtml, scanFailed, failurePanel } from './_shared.js';

// YARA `severity` (from `score`/`severity` meta) is numeric (0-100) or a
// word. Same buckets as RiskCalculator.severity_label on the server.
const WORD_SCORES = { critical: 100, high: 80, medium: 50, low: 20, info: 5 };
function severityScore(value) {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') {
        const n = parseInt(value, 10);
        if (!Number.isNaN(n)) return n;
        return WORD_SCORES[value.trim().toLowerCase()] ?? 50;
    }
    return 50;
}
function severityClass(score) {
    return score >= 70 ? 'critical' : 'medium';
}

export default {
    id: 'yara',
    elementId: 'yaraResults',
    statsElementId: 'yaraStats',

    render(results, ctx) {
        if (scanFailed(results)) {
            ctx.element.innerHTML = failurePanel(results);
            return;
        }

        const matches = Array.isArray(results.matches) ? results.matches : [];
        const matchCount = matches.length;
        const isClean = matchCount === 0;
        const totalStrings = matches.reduce((acc, m) => acc + (Array.isArray(m.strings) ? m.strings.length : 0), 0);
        const highestSeverity = matches.length > 0 ? Math.max(...matches.map(m => severityScore(m.metadata?.severity))) : 0;

        ctx.statsElement.innerHTML = statRow([
            { label: 'Rule Matches',  value: matchCount,    severity: isClean ? 'clean' : 'critical' },
            { label: 'Total Strings', value: totalStrings,  severity: 'info' },
            { label: 'Status',        value: isClean ? 'Clean' : `Sev ${highestSeverity}`,
                                      severity: isClean ? 'clean' : severityClass(highestSeverity) },
        ]);

        let html = '';

        if (results.scan_info?.target) {
            html += panel('Target', `
                <div class="lb-mono lb-strong" style="font-size: 13px; word-break: break-all;">${escapeHtml(results.scan_info.target)}</div>
                ${results.scan_info.rules_file ? `<div class="lb-muted" style="font-size: 12px; margin-top: 4px;">Rules: ${escapeHtml(results.scan_info.rules_file)}</div>` : ''}
            `);
        }

        if (isClean) {
            html += cleanState('No rules matched', 'All YARA rules passed without matching.');
            ctx.element.innerHTML = html;
            return;
        }

        const sortedMatches = [...matches].sort((a, b) =>
            severityScore(b.metadata?.severity) - severityScore(a.metadata?.severity)
        );

        const labelMap = {
            threat_name:   'Match',
            rule_filepath: 'Rule File',
            creation_date: 'Created',
            id:            'Rule ID',
        };
        const metaOrder = ['threat_name', 'rule_filepath', 'creation_date', 'id'];

        html += sortedMatches.map((match, i) => {
            const severity = severityScore(match.metadata?.severity);
            const sev = severityClass(severity);
            const strings = Array.isArray(match.strings) ? match.strings : [];

            const metaPairs = metaOrder
                .filter(k => match.metadata?.[k])
                .map(k => [labelMap[k], match.metadata[k]]);

            return `
                <div class="lb-panel">
                    <div class="lb-panel-hdr">
                        <span class="lb-glyph">▸</span>
                        <span class="lb-mono" style="color: ${sev === 'critical' ? 'var(--lb-accent)' : 'var(--lb-sev-medium)'};">#${i + 1} ${escapeHtml(match.rule)}</span>
                        <span style="margin-left: auto; display: flex; gap: 6px;">
                            ${tag(sev, `Sev ${severity}`)}
                            ${strings.length ? `<span class="lb-tag muted">${strings.length} strings</span>` : ''}
                        </span>
                    </div>
                    ${metaPairs.length ? `<div class="lb-panel-body">${kvGrid(metaPairs, 2)}</div>` : ''}
                    ${strings.length ? `
                        <div class="lb-panel-body" style="border-top: 1px solid var(--lb-border);">
                            <div class="lb-eyebrow" style="margin-bottom: 6px;">String Matches</div>
                            <div style="display:flex; flex-direction:column; gap: 6px;">
                                ${strings.map(str => `
                                    <div style="border: 1px solid var(--lb-border); padding: 8px;">
                                        <div style="display:flex; align-items:center; gap:8px; margin-bottom: 4px;">
                                            <span class="lb-mono lb-muted" style="font-size: 12px;">${escapeHtml(str.offset || '')}</span>
                                            ${str.identifier ? `<span class="lb-tag muted">${escapeHtml(str.identifier)}</span>` : ''}
                                            ${str.data_type ? `<span class="lb-tag muted">${escapeHtml(str.data_type)}</span>` : ''}
                                        </div>
                                        <pre class="lb-mono" style="background: var(--lb-bg); padding: 6px 8px; font-size: 12px; color: var(--lb-text-dim); white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow: auto; margin: 0;">${escapeHtml(str.data || '')}</pre>
                                        ${str.definition ? `<div class="lb-muted lb-mono" style="font-size: 11px; margin-top: 4px; word-break: break-all;">Rule: ${escapeHtml(str.definition)}</div>` : ''}
                                    </div>
                                `).join('')}
                            </div>
                        </div>` : ''}
                </div>`;
        }).join('');

        ctx.element.innerHTML = html;
    },
};
