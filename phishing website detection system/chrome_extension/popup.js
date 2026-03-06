/* ═══════════════════════════════════════════════════════════════
   Phishing Shield – Popup Logic
   Reads the active tab URL, sends it to the Flask backend,
   and renders the prediction result in the popup UI.
   ═══════════════════════════════════════════════════════════════ */

const API_BASE = 'http://localhost:5000';

// ── DOM References ─────────────────────────────────────────────
const urlEl = document.getElementById('current-url');
const scanBtn = document.getElementById('scan-btn');
const resultCard = document.getElementById('result-card');
const resultIconWrap = document.getElementById('result-icon-wrapper');
const resultTitle = document.getElementById('result-title');
const resultDesc = document.getElementById('result-description');
const confidenceVal = document.getElementById('confidence-value');
const confidenceFill = document.getElementById('confidence-fill');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');

let currentUrl = '';

// ── Helper: check if the URL is a real website (http/https) ───
function isScannableUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
        return false;
    }
}

// ── SVG Icons (inline so we don't need extra files) ───────────
const ICONS = {
    safe: `<svg viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7V12C3 17.25 6.75 22.13 12 23C17.25 22.13 21 17.25 21 12V7L12 2Z" fill="rgba(52,211,153,0.15)" stroke="#34d399" stroke-width="2"/><path d="M9 12L11 14L15 10" stroke="#34d399" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    danger: `<svg viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7V12C3 17.25 6.75 22.13 12 23C17.25 22.13 21 17.25 21 12V7L12 2Z" fill="rgba(248,113,113,0.15)" stroke="#f87171" stroke-width="2"/><path d="M12 9V13M12 17H12.01" stroke="#f87171" stroke-width="2" stroke-linecap="round"/></svg>`,
    loading: `<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="rgba(108,158,255,0.3)" stroke-width="2"/><path d="M12 2A10 10 0 0 1 22 12" stroke="#6c9eff" stroke-width="2" stroke-linecap="round"><animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/></path></svg>`,
};

// ── 1. Get Current Tab URL ─────────────────────────────────────
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.url) {
        currentUrl = tabs[0].url;
        urlEl.textContent = currentUrl;
    } else {
        urlEl.textContent = 'Unable to read URL';
        scanBtn.disabled = true;
    }
});

// ── 2. Check Backend Health ────────────────────────────────────
async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`, { method: 'GET' });
        if (res.ok) {
            statusDot.className = 'status-dot online';
            statusText.textContent = 'Backend connected';
            return true;
        }
    } catch (_) { /* fall through */ }

    statusDot.className = 'status-dot offline';
    statusText.textContent = 'Backend offline — start app.py';
    return false;
}

checkHealth();

// ── 3. Scan Button Handler ─────────────────────────────────────
scanBtn.addEventListener('click', async () => {
    if (!currentUrl) return;

    // ── Guard: only scan real http/https websites ──
    if (!isScannableUrl(currentUrl)) {
        showResult(
            'safe',
            'ℹ️ Not a Website',
            `This is a browser internal page (${currentUrl.split(':')[0]}://). It is not a real website and does not need phishing detection.`,
            null,
        );
        return;
    }

    // ── Show loading state ──
    scanBtn.disabled = true;
    scanBtn.classList.add('scanning');
    scanBtn.innerHTML = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="rgba(255,255,255,0.3)" stroke-width="2"/><path d="M12 2A10 10 0 0 1 22 12" stroke="#fff" stroke-width="2" stroke-linecap="round"><animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="0.8s" repeatCount="indefinite"/></path></svg> Scanning…`;

    showResult('loading', 'Analyzing…', 'Sending URL to the ML model…', null);

    try {
        const res = await fetch(`${API_BASE}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl }),
        });

        if (!res.ok) throw new Error(`Server responded ${res.status}`);

        const data = await res.json();
        const isSafe = data.prediction === 'good';

        showResult(
            isSafe ? 'safe' : 'danger',
            isSafe ? '✅ Safe Website' : '🚨 Phishing Detected!',
            isSafe
                ? 'This URL appears to be legitimate. No phishing indicators were found by the ML model.'
                : 'Warning! This URL exhibits phishing characteristics. Be cautious — do NOT enter any personal information on this site.',
            data.confidence,
        );
    } catch (err) {
        showResult(
            'danger',
            '⚠️ Scan Failed',
            `Could not reach the backend server. Make sure app.py is running.\n\nError: ${err.message}`,
            null,
        );
    }

    // Reset button
    scanBtn.disabled = false;
    scanBtn.classList.remove('scanning');
    scanBtn.innerHTML = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none"><path d="M21 21L16.65 16.65M19 11A8 8 0 1 1 3 11a8 8 0 0 1 16 0Z" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg> Scan Again`;
});

// ── 4. Render Result Card ──────────────────────────────────────
function showResult(type, title, description, confidence) {
    resultCard.classList.remove('hidden', 'safe', 'danger', 'loading');
    resultCard.classList.add(type);

    resultIconWrap.className = `result-icon-wrapper ${type}`;
    resultIconWrap.innerHTML = ICONS[type] || ICONS.loading;

    resultTitle.textContent = title;
    resultTitle.style.color = type === 'safe' ? '#34d399' : type === 'danger' ? '#f87171' : '#6c9eff';
    resultDesc.textContent = description;

    if (confidence !== null && confidence !== undefined) {
        confidenceVal.textContent = `${confidence}%`;
        confidenceFill.style.width = `${confidence}%`;
        confidenceFill.className = `confidence-fill ${type}`;
    } else {
        confidenceVal.textContent = '—';
        confidenceFill.style.width = '0%';
    }
}
