// app/static/js/utils/escape.js
// XSS-safe HTML escaping for every value interpolated into innerHTML /
// template literals (sample-derived strings are attacker-controlled).

const HTML_ESCAPE_MAP = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;',
};

const HTML_ESCAPE_RE = /[&<>"'`=\/]/g;

export function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text).replace(HTML_ESCAPE_RE, (ch) => HTML_ESCAPE_MAP[ch]);
}
