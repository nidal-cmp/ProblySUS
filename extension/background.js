const API_URL = "http://localhost:5000/analyze";

// Track active scans to prevent duplicates and race conditions
const activeScans = new Map();

// Helper to normalize URL for storage keys and deduplication
function getNormalizedUrl(url) {
    try {
        const u = new URL(url);
        // Strip protocol, www., and trailing slashes. Keep path and domain.
        let domain = u.hostname.toLowerCase();
        if (domain.startsWith('www.')) domain = domain.substring(4);
        let path = u.pathname.replace(/\/+$/, '');
        return `${domain}${path}`;
    } catch (e) {
        return url.toLowerCase();
    }
}

// 1. Listen for tab updates to trigger auto-scan and reset badge
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Reset badge immediately when navigation starts (URL changes)
    if (changeInfo.url && tab.url && tab.url.startsWith('http')) {
        chrome.action.setBadgeText({ text: "", tabId: tabId });
    }

    // Trigger analysis when the page is fully loaded
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        const normUrl = getNormalizedUrl(tab.url);
        console.log(`Auto-scanning: ${normUrl}`);
        performAnalysis(tab.url, tabId);
    }
});

// 2. Clear badge when a tab is activated if no data exists (prevents ghost badges)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (tab.url && tab.url.startsWith('http')) {
            const normUrl = getNormalizedUrl(tab.url);
            const storageKey = `scan_${normUrl}`;
            const stored = await chrome.storage.local.get(storageKey);
            if (stored[storageKey]) {
                updateBadge(stored[storageKey].data, activeInfo.tabId);
            } else {
                chrome.action.setBadgeText({ text: "", tabId: activeInfo.tabId });
            }
        } else {
            chrome.action.setBadgeText({ text: "", tabId: activeInfo.tabId });
        }
    } catch (e) {
        console.error("Tab activation badge update failed:", e);
    }
});

async function performAnalysis(url, tabId) {
    const normUrl = getNormalizedUrl(url);

    // If already scanning this URL, return the existing promise
    if (activeScans.has(normUrl)) {
        console.log(`Using active scan for ${normUrl}`);
        return activeScans.get(normUrl);
    }

    const scanPromise = (async () => {
        try {
            // Set loading state on badge
            if (tabId) {
                chrome.action.setBadgeText({ text: "...", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#3B82F6", tabId: tabId });
            }

        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${response.status}`);
        }

            const result = await response.json();
            
            // Save to storage for the popup to read
            const storageKey = `scan_${normUrl}`;
            await chrome.storage.local.set({ [storageKey]: {
                data: result.data || result,
                timestamp: Date.now()
            }});

            // Update Badge based on score/label
            updateBadge(result.data || result, tabId);

            return result;

        } catch (error) {
            console.error("Analysis error:", error);
            if (tabId) {
                chrome.action.setBadgeText({ text: "ERR", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#EF4444", tabId: tabId });
            }
            throw error; // Rethrow so the promise rejected state is captured
        } finally {
            activeScans.delete(normUrl);
        }
    })();

    activeScans.set(normUrl, scanPromise);
    return scanPromise;
}

function updateBadge(data, tabId) {
    if (!data) return;
    
    const score = Math.round(data.riskScore || 0);
    const label = data.label || 'Unknown';
    
    // Set badge text to score
    chrome.action.setBadgeText({ text: score.toString(), tabId: tabId });
    
    // Set color based on label
    let color = "#10B981"; // Safe
    if (label === 'Caution' || label === 'Suspicious') {
        color = "#F59E0B"; 
    } else if (label === 'Fraudulent' || label === 'Danger' || score > 70) {
        color = "#EF4444"; 
    }
    
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
}

// 3. Keep existing message listener for manual scans/compatibility
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze_url") {
        performAnalysis(request.url, sender.tab?.id)
            .then(data => {
                if (data) sendResponse({ data: data });
                else sendResponse({ error: "Background analysis failed to return data." });
            })
            .catch(error => sendResponse({ error: error.message || "Unknown background error" }));
        return true;
    }
});
