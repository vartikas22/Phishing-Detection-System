/* ═══════════════════════════════════════════════════════════════
   Phishing Shield – Background Service Worker (Manifest V3)
   Runs silently in the background. Can be extended for 
   automatic scanning, notifications, etc.
   ═══════════════════════════════════════════════════════════════ */

const API_BASE = 'http://localhost:5000';

// Listen for extension installation
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('🛡️ Phishing Shield installed successfully.');
  }
});

// Optional: Auto-scan when a tab finishes loading
// Uncomment the block below to enable automatic background scanning
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Skip chrome:// and extension pages 
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) return;

    try {
      const res = await fetch(`${API_BASE}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url }),
      });

      if (!res.ok) return;
      const data = await res.json();

      if (data.prediction === 'bad') {
        // Change extension icon badge to warn user
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#f87171', tabId });
      } else {
        chrome.action.setBadgeText({ text: '✓', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#34d399', tabId });
      }
    } catch (err) {
      console.warn('Phishing Shield: backend unreachable', err.message);
    }
  }
});
