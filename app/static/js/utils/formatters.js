// app/static/js/utils/formatters.js
// Human-readable formatting helpers.

const SIZE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

export function formatBytes(bytes) {
    if (bytes === null || bytes === undefined) return 'N/A';
    const n = Number(bytes);
    if (!Number.isFinite(n) || n < 0) return 'N/A';
    if (n === 0) return '0 B';
    const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), SIZE_UNITS.length - 1);
    return `${(n / Math.pow(1024, i)).toFixed(2)} ${SIZE_UNITS[i]}`;
}
