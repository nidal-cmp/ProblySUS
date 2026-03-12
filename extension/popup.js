// popup.js
document.addEventListener('DOMContentLoaded', async () => {
  const urlHeader = document.getElementById('url-header');
  const urlDisplay = document.getElementById('url-display');
  const scanBtn = document.getElementById('scan-btn');
  const loadingDiv = document.getElementById('loading');
  const resultContainer = document.getElementById('result-container');

  // Result Elements
  const scoreArcFill = document.getElementById('score-arc');
  const scoreValue = document.getElementById('score-value');
  const riskLabel = document.getElementById('risk-label');
  const recommendation = document.getElementById('recommendation');
  const reasonsUl = document.getElementById('reasons-ul');

  const detailSsl = document.getElementById('detail-ssl');
  const iconSsl = document.getElementById('icon-ssl');
  const detailAge = document.getElementById('detail-age');
  const detailBlacklist = document.getElementById('detail-blacklist');
  const iconBlacklist = document.getElementById('icon-blacklist');
  const detailMx = document.getElementById('detail-mx');
  const iconMx = document.getElementById('icon-mx');

  const fullReportBtn = document.getElementById('full-report-btn');

  // 1. Get current active tab URL
  let currentTabUrl = '';

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0) {
      currentTabUrl = tabs[0].url;

      // Don't auto-scan internal pages
      if (currentTabUrl.startsWith('chrome://') || currentTabUrl.startsWith('edge://')) {
        urlHeader.classList.remove('hidden');
        urlDisplay.textContent = currentTabUrl;

        // Show artificial error immediately
        loadingDiv.classList.add('hidden');
        resultContainer.classList.add('hidden');

        const html = document.createElement('div');
        html.style.color = 'var(--danger)';
        html.style.textAlign = 'center';
        html.style.padding = '20px';
        html.style.fontSize = '14px';
        html.innerHTML = 'Cannot analyze browser settings pages.<br><br>Please run on a standard website.';
        document.querySelector('.container').appendChild(html);
        return;
      }

      // Show scan button
      urlHeader.classList.remove('hidden');
      urlDisplay.textContent = currentTabUrl.length > 40 ? currentTabUrl.substring(0, 37) + '...' : currentTabUrl;
      scanBtn.classList.remove('hidden');

    }
  } catch (err) {
    urlHeader.classList.remove('hidden');
    urlDisplay.textContent = 'Error reading tab info.';
  }

  // 2. Scan Button Logic
  scanBtn.addEventListener('click', runScan);

  function runScan() {
    if (!currentTabUrl) return;

    urlHeader.classList.add('hidden');
    scanBtn.classList.add('hidden');
    resultContainer.classList.add('hidden');
    loadingDiv.classList.remove('hidden');

    try {
      chrome.runtime.sendMessage(
        { action: "analyze_url", url: currentTabUrl },
        (response) => {
          loadingDiv.classList.add('hidden');

          if (chrome.runtime.lastError || !response) {
            showError("Could not connect to the extension background process.");
            return;
          }

          if (response.error) {
            showError(response.error);
            return;
          }

          if (response.data) {
            displayResults(response.data);
          } else {
            showError("Unknown error occurred during analysis.");
          }
        }
      );
    } catch (err) {
      loadingDiv.classList.add('hidden');
      showError(err.message || 'Failed to scan URL.');
    }
  }

  // Open full report
  fullReportBtn.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'http://localhost:5173/?url=' + encodeURIComponent(currentTabUrl) + '&from=extension' });
  });

  function showError(msg) {
    urlHeader.classList.remove('hidden');
    urlDisplay.textContent = currentTabUrl;
    scanBtn.classList.remove('hidden');

    const errDiv = document.createElement('div');
    errDiv.style.backgroundColor = 'var(--danger-glow)';
    errDiv.style.border = '1px solid var(--danger)';
    errDiv.style.borderRadius = '8px';
    errDiv.style.padding = '12px';
    errDiv.style.color = 'var(--danger)';
    errDiv.style.textAlign = 'center';
    errDiv.style.fontSize = '14px';
    errDiv.style.marginTop = '16px';
    errDiv.textContent = msg;

    if (msg.toLowerCase().includes('connect') || msg.toLowerCase().includes('http') || msg.toLowerCase().includes('fetch')) {
      const p = document.createElement('p');
      p.style.fontSize = '12px';
      p.style.marginTop = '6px';
      p.style.color = 'var(--text-muted)';
      p.textContent = 'Ensure the local ProblySUS server is running on port 5000.';
      errDiv.appendChild(p);
    }

    document.querySelector('.container').appendChild(errDiv);
  }

  function displayResults(data) {
    urlHeader.classList.remove('hidden');
    urlDisplay.textContent = currentTabUrl.length > 40 ? currentTabUrl.substring(0, 37) + '...' : currentTabUrl;

    resultContainer.classList.remove('hidden');

    // Set score
    const score = Math.round(data.riskScore || 0);
    scoreValue.textContent = score;

    // Arc Calculation (-135deg to +45deg is a 180 degree semi-circle)
    setTimeout(() => {
      const rotation = -135 + (180 * (score / 100));
      scoreArcFill.style.transform = `rotate(${rotation}deg)`;
    }, 50);

    // Style based on label
    if (data.label === 'Safe') {
      scoreArcFill.style.borderColor = 'var(--safe)';
      riskLabel.style.color = 'var(--safe)';
    } else if (data.label === 'Caution' || data.label === 'Suspicious') {
      scoreArcFill.style.borderColor = 'var(--caution)';
      riskLabel.style.color = 'var(--caution)';
    } else {
      scoreArcFill.style.borderColor = 'var(--danger)';
      riskLabel.style.color = 'var(--danger)';
    }

    // Set Text
    riskLabel.textContent = data.label || 'Unknown';
    recommendation.textContent = data.recommendation || '';

    // Set metrics row
    // HTTPS
    if (data.checks?.https) {
      detailSsl.textContent = 'HTTPS';
      detailSsl.style.color = 'var(--safe)';
      iconSsl.textContent = '🔒';
    } else {
      detailSsl.textContent = 'HTTP';
      detailSsl.style.color = 'var(--danger)';
      iconSsl.textContent = '🔓';
    }

    // Age
    const age = data.checks?.domainAgeDays || 0;
    detailAge.textContent = age > 0 ? `${age}d` : '?';

    // Blacklist
    let isBl = false;
    if (typeof data.checks?.blacklisted === 'boolean') {
      isBl = data.checks?.blacklisted;
    } else if (data.checks?.blacklisted?.listed === true) {
      isBl = true;
    }

    if (isBl) {
      detailBlacklist.textContent = 'Listed';
      detailBlacklist.style.color = 'var(--danger)';
      iconBlacklist.textContent = '🚫';
    } else {
      detailBlacklist.textContent = 'Clean';
      detailBlacklist.style.color = 'var(--safe)';
      iconBlacklist.textContent = '✅';
    }

    // Email/MX
    if (data.checks?.mxRecords) {
      detailMx.textContent = 'MX';
      detailMx.style.color = 'var(--safe)';
      iconMx.textContent = '📧';
    } else {
      detailMx.textContent = 'None';
      detailMx.style.color = 'var(--danger)';
      iconMx.textContent = '❌';
    }

    // Set Reasons list
    reasonsUl.innerHTML = '';
    const reasonsList = data.reasons || [];

    if (reasonsList.length === 0) {
      const li = document.createElement('li');
      li.textContent = "No significant security issues found.";
      reasonsUl.appendChild(li);
    } else {
      reasonsList.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;

        // rudimentary styling based on keywords
        const rLower = reason.toLowerCase();
        if (rLower.includes('blacklisted') || rLower.includes('danger') || rLower.includes('fraud')) {
          li.className = 'danger';
        } else if (rLower.includes('warning') || rLower.includes('suspicious') || rLower.includes('no https')) {
          li.className = 'warn';
        }

        reasonsUl.appendChild(li);
      });
    }

    // Map Extra Tab Data
    const behaviorUl = document.getElementById('behavior-ul');
    const privacyUl = document.getElementById('privacy-ul');
    behaviorUl.innerHTML = '';
    privacyUl.innerHTML = '';

    // Behavior Tab
    if (data.analysis?.behavior) {
      if (data.analysis.behavior.error) {
        behaviorUl.innerHTML = `<li class="text-muted">${data.analysis.behavior.error}</li>`;
      } else {
        const b = data.analysis.behavior;
        behaviorUl.innerHTML = '';

        // Stats row
        behaviorUl.innerHTML += `<li class="stats-row">
          <div class="stat-item">
            <div class="stat-value ${b.redirect_count > 3 ? 'danger' : b.redirect_count > 1 ? 'caution' : 'safe'}">${b.redirect_count || 0}</div>
            <div class="stat-label">Redirects</div>
          </div>
          <div class="stat-item">
            <div class="stat-value ${b.external_request_count > 20 ? 'caution' : 'safe'}">${b.external_request_count || 0}</div>
            <div class="stat-label">Ext. Requests</div>
          </div>
          <div class="stat-item">
            <div class="stat-value ${(b.suspicious_domains?.length || 0) > 0 ? 'danger' : 'safe'}">${b.suspicious_domains?.length || 0}</div>
            <div class="stat-label">Susp. Domains</div>
          </div>
        </li>`;

        // Suspicious domains
        if (b.suspicious_domains && b.suspicious_domains.length > 0) {
          behaviorUl.innerHTML += `<li class="warning-section">
            <div class="warning-header">⚠️ Suspicious domains contacted:</div>
            <div class="domain-tags">`;
          b.suspicious_domains.forEach(domain => {
            behaviorUl.innerHTML += `<span class="domain-tag danger">${domain}</span>`;
          });
          behaviorUl.innerHTML += `</div></li>`;
        }

        // Redirect chain
        if (b.redirect_chain && b.redirect_chain.length > 1) {
          behaviorUl.innerHTML += `<li class="chain-section">
            <div class="chain-header">Redirect chain:</div>
            <div class="chain-list">`;
          b.redirect_chain.slice(0, 3).forEach((url, i) => {
            behaviorUl.innerHTML += `<div class="chain-item">${i + 1}. <span class="chain-url">${url}</span></div>`;
          });
          if (b.redirect_chain.length > 3) {
            behaviorUl.innerHTML += `<div class="chain-more">...and ${b.redirect_chain.length - 3} more</div>`;
          }
          behaviorUl.innerHTML += `</div></li>`;
        }

        // Page title
        if (b.page_title) {
          behaviorUl.innerHTML += `<li class="page-title">Page title: <span class="title-text">${b.page_title}</span></li>`;
        }
      }
    } else {
      behaviorUl.innerHTML = '<li class="text-muted">No behavior data.</li>';
    }

    // Network Tab with Trackers
    if (data.analysis?.network) {
      if (data.analysis.network.error) {
        document.getElementById('trackers-list').innerHTML = `<li class="text-muted">${data.analysis.network.error}</li>`;
      } else {
        const n = data.analysis.network;

        // Set risk level badge
        const riskColors = {
          low: 'safe',
          medium: 'caution',
          high: 'danger'
        };
        const riskColor = riskColors[n.risk_level] || 'safe';
        const riskBadge = document.getElementById('risk-badge');
        riskBadge.className = `risk-badge ${riskColor}`;
        riskBadge.textContent = (n.risk_level || 'Unknown').toUpperCase() + ' Risk';

        // Set stats
        document.getElementById('external-count').textContent = n.external_domain_count || 0;
        document.getElementById('cdn-count').textContent = n.safe_infra_domains?.length || 0;
        
        const suspiciousCount = n.suspicious_external_count || 0;
        const suspiciousEl = document.getElementById('suspicious-count');
        suspiciousEl.textContent = suspiciousCount;
        if (suspiciousCount > 0) {
          suspiciousEl.className = 'stat-number danger';
        } else {
          suspiciousEl.className = 'stat-number safe';
        }
      }

      // Set up trackers section
      if (data.analysis?.trackers) {
        const t = data.analysis.trackers;
        const trackerCount = t.tracker_count || 0;
        const trackersList = document.getElementById('trackers-list');

        // Update badge
        const trackerBadge = document.getElementById('tracker-badge');
        trackerBadge.textContent = `${trackerCount} found`;
        if (trackerCount > 8) {
          trackerBadge.className = 'tracker-badge high';
        } else if (trackerCount > 4) {
          trackerBadge.className = 'tracker-badge medium';
        } else {
          trackerBadge.className = 'tracker-badge';
        }

        // Populate trackers
        if (trackerCount === 0) {
          trackersList.innerHTML = '<li class="text-muted">No known trackers detected.</li>';
        } else {
          trackersList.innerHTML = '';
          const elementIcons = {
            'script': '📜',
            'iframe': '🪟',
            'img': '🖼️',
            'link': '🔗',
            'inline_script': '💻',
          };

          (t.tracker_details || []).forEach(tracker => {
            const icon = elementIcons[tracker.element] || '📦';
            const item = document.createElement('li');
            item.className = 'tracker-item';
            item.innerHTML = `
              <div class="tracker-info">
                <span class="tracker-icon">${icon}</span>
                <div class="tracker-details">
                  <div class="tracker-name">${tracker.name}</div>
                  <div class="tracker-domain">${tracker.domain}</div>
                </div>
              </div>
              <span class="tracker-type">${tracker.element}</span>
            `;
            trackersList.appendChild(item);
          });
        }
      }
    } else {
      document.getElementById('external-count').textContent = '0';
      document.getElementById('cdn-count').textContent = '0';
      document.getElementById('suspicious-count').textContent = '0';
      document.getElementById('trackers-list').innerHTML = '<li class="text-muted">No network data.</li>';
    }

    // Privacy Tab
    if (data.analysis?.privacy) {
      if (data.analysis.privacy.error) {
        privacyUl.innerHTML = `<li class="text-muted">${data.analysis.privacy.error}</li>`;
      } else {
        const p = data.analysis.privacy;
        privacyUl.innerHTML = '';

        // Privacy grade header
        const gradeConfig = {
          good: { color: 'safe', emoji: '🟢', label: 'Good' },
          moderate: { color: 'caution', emoji: '🟡', label: 'Moderate' },
          poor: { color: 'caution', emoji: '🟠', label: 'Poor' },
          invasive: { color: 'danger', emoji: '🔴', label: 'Invasive' }
        };
        const grade = gradeConfig[p.privacy_grade] || gradeConfig.good;
        privacyUl.innerHTML += `<li class="grade-header">
          <span class="grade-label">Privacy Grade:</span>
          <span class="grade-badge ${grade.color}">${grade.emoji} ${grade.label}</span>
        </li>`;

        // Privacy exposure bar
        const privacyScore = Math.min(10,
          Math.floor(
            (p.tracking_cookie_count || 0) * 1.5 +
            (p.third_party_script_count || 0) * 0.5 +
            (p.fingerprinting_score || 0) * 1.5
          )
        );
        privacyUl.innerHTML += `<li class="exposure-bar">
          <div class="exposure-label">
            <span>Privacy Exposure</span>
            <span class="exposure-score ${privacyScore > 6 ? 'danger' : privacyScore > 3 ? 'caution' : 'safe'}">${privacyScore}/10</span>
          </div>
          <div class="exposure-track">
            <div class="exposure-fill ${privacyScore > 6 ? 'danger-bg' : privacyScore > 3 ? 'caution-bg' : 'safe-bg'}" style="width: ${privacyScore * 10}%"></div>
          </div>
        </li>`;

        // Stats grid
        privacyUl.innerHTML += `<li class="stats-row">
          <div class="stat-item">
            <div class="stat-value safe">🍪 ${p.cookie_count || 0}</div>
            <div class="stat-label">Cookies</div>
          </div>
          <div class="stat-item">
            <div class="stat-value ${(p.tracking_cookie_count || 0) > 3 ? 'danger' : 'safe'}">🎯 ${p.tracking_cookie_count || 0}</div>
            <div class="stat-label">Tracking</div>
          </div>
          <div class="stat-item">
            <div class="stat-value ${(p.third_party_script_count || 0) > 5 ? 'caution' : 'safe'}">📜 ${p.third_party_script_count || 0}</div>
            <div class="stat-label">3P Scripts</div>
          </div>
          <div class="stat-item">
            <div class="stat-value ${(p.fingerprinting_score || 0) > 2 ? 'caution' : 'safe'}">🔬 ${p.fingerprinting_score || 0}</div>
            <div class="stat-label">Fingerprint</div>
          </div>
        </li>`;

        // Fingerprinting techniques
        if (p.fingerprinting_signals && p.fingerprinting_signals.length > 0) {
          const fingerprintIcons = {
            canvas: '🎨', webgl: '🖥️', audio: '🔊', plugins: '🔌',
            language: '🌍', screen: '📺', hardware: '💻', battery: '🔋', webrtc: '📡'
          };
          privacyUl.innerHTML += `<li class="fingerprint-section">
            <div class="fingerprint-header">Fingerprinting techniques:</div>
            <div class="technique-tags">`;
          p.fingerprinting_signals.forEach(signal => {
            const icon = fingerprintIcons[signal] || '❓';
            privacyUl.innerHTML += `<span class="technique-tag caution">${icon} ${signal}</span>`;
          });
          privacyUl.innerHTML += `</div></li>`;
        }

        // Tracking cookies (collapsible)
        if (p.tracking_cookie_names && p.tracking_cookie_names.length > 0) {
          privacyUl.innerHTML += `<li class="cookie-breakdown">
            <div class="cookie-toggle" data-count="${p.tracking_cookie_names.length}">View ${p.tracking_cookie_names.length} tracking cookie(s) ▼</div>
            <div class="cookie-list hidden">`;
          p.tracking_cookie_names.slice(0, 8).forEach(name => {
            privacyUl.innerHTML += `<span class="cookie-name">${name}</span>`;
          });
          if (p.tracking_cookie_names.length > 8) {
            privacyUl.innerHTML += `<span class="cookie-more">...and ${p.tracking_cookie_names.length - 8} more</span>`;
          }
          privacyUl.innerHTML += `</div></li>`;
        }
      }
    } else {
      privacyUl.innerHTML = '<li class="text-muted">No privacy data.</li>';
    }
  }

  // Set up Tab Click Listeners
  const tabItems = document.querySelectorAll('.tab-item');
  const tabContents = document.querySelectorAll('.tab-content');

  tabItems.forEach((tab, index) => {
    tab.addEventListener('click', () => {
      // Deactivate all
      tabItems.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.add('hidden'));

      // Activate clicked
      tab.classList.add('active');
      if (tabContents[index]) {
        tabContents[index].classList.remove('hidden');
      }
    });
  });

  // Set up collapsible toggles
  setupCollapsibleToggles();
});

function setupCollapsibleToggles() {
  // Domain breakdown toggle
  const breakdownToggle = document.querySelector('.breakdown-toggle');
  if (breakdownToggle) {
    breakdownToggle.addEventListener('click', () => {
      const domainList = breakdownToggle.nextElementSibling;
      if (domainList) {
        const isHidden = domainList.classList.contains('hidden');
        domainList.classList.toggle('hidden');
        const count = breakdownToggle.dataset.count || '0';
        breakdownToggle.textContent = isHidden
          ? `View all ${count} external domains ▲`
          : `View all ${count} external domains ▼`;
      }
    });
  }

  // Cookie breakdown toggle
  const cookieToggle = document.querySelector('.cookie-toggle');
  if (cookieToggle) {
    cookieToggle.addEventListener('click', () => {
      const cookieList = cookieToggle.nextElementSibling;
      if (cookieList) {
        const isHidden = cookieList.classList.contains('hidden');
        cookieList.classList.toggle('hidden');
        const count = cookieToggle.dataset.count || '0';
        cookieToggle.textContent = isHidden
          ? `View ${count} tracking cookie(s) ▲`
          : `View ${count} tracking cookie(s) ▼`;
      }
    });
  }
}
