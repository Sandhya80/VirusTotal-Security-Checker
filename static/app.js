// --- Auth State ---
let authToken = localStorage.getItem('authToken') || null;
let currentUser = JSON.parse(localStorage.getItem('currentUser') || 'null');

function updateAuthUI() {
  const authNavbar = document.getElementById('auth-navbar');
  if (!authNavbar) return;
  authNavbar.innerHTML = '';
  if (authToken && currentUser) {
    // Show user dropdown and logout
    const dropdown = document.createElement('div');
    dropdown.className = 'dropdown';
    dropdown.innerHTML = `
      <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
        <i class="bi bi-person-circle"></i> ${currentUser.full_name || currentUser.email}
      </button>
      <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
        <li><span class="dropdown-item-text">${currentUser.email}</span></li>
        <li><hr class="dropdown-divider"></li>
        <li><a class="dropdown-item text-danger" href="#" id="logout-link">Logout</a></li>
      </ul>
    `;
    authNavbar.appendChild(dropdown);
    document.getElementById('logout-link').onclick = handleLogout;
  } else {
    // Show login/register
    authNavbar.innerHTML = `
      <button class="btn btn-outline-primary me-2" id="login-btn" data-bs-toggle="modal" data-bs-target="#loginModal">Login</button>
      <button class="btn btn-primary" id="register-btn" data-bs-toggle="modal" data-bs-target="#registerModal">Register</button>
    `;
  }
}

function handleRegister(e) {
  e.preventDefault();
  const email = document.getElementById('register-email').value.trim();
  const password = document.getElementById('register-password').value;
  const fullName = document.getElementById('register-fullname').value.trim();
  const errorDiv = document.getElementById('register-error');
  errorDiv.style.display = 'none';
  fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, full_name: fullName })
  })
    .then(r => r.json().then(data => ({ ok: r.ok, data })))
    .then(({ ok, data }) => {
      if (ok) {
        // Auto-login after register
        document.getElementById('registerForm').reset();
        bootstrap.Modal.getOrCreateInstance(document.getElementById('registerModal')).hide();
        handleLoginDirect(email, password);
      } else {
        errorDiv.textContent = data.detail || data.msg || 'Registration failed.';
        errorDiv.style.display = '';
      }
    })
    .catch(() => {
      errorDiv.textContent = 'Registration failed.';
      errorDiv.style.display = '';
    });
}

function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  handleLoginDirect(email, password);
}

function handleLoginDirect(email, password) {
  const errorDiv = document.getElementById('login-error');
  errorDiv.style.display = 'none';
  const form = new URLSearchParams();
  form.append('username', email);
  form.append('password', password);
  fetch('/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form
  })
    .then(r => r.json().then(data => ({ ok: r.ok, data })))
    .then(({ ok, data }) => {
      if (ok && data.access_token) {
        authToken = data.access_token;
        currentUser = data.user;
        localStorage.setItem('authToken', authToken);
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        document.getElementById('loginForm').reset();
        bootstrap.Modal.getOrCreateInstance(document.getElementById('loginModal')).hide();
        updateAuthUI();
      } else {
        errorDiv.textContent = data.detail || 'Login failed.';
        errorDiv.style.display = '';
      }
    })
    .catch(() => {
      errorDiv.textContent = 'Login failed.';
      errorDiv.style.display = '';
    });
}

function handleLogout(e) {
  e && e.preventDefault();
  authToken = null;
  currentUser = null;
  localStorage.removeItem('authToken');
  localStorage.removeItem('currentUser');
  updateAuthUI();
}

// Attach handlers on DOMContentLoaded
document.addEventListener('DOMContentLoaded', function () {
  updateAuthUI();
  const loginForm = document.getElementById('loginForm');
  if (loginForm) loginForm.onsubmit = handleLogin;
  const registerForm = document.getElementById('registerForm');
  if (registerForm) registerForm.onsubmit = handleRegister;
});
// Vectara Search UI logic
document.addEventListener('DOMContentLoaded', function() {
    const searchFormRAG = document.getElementById('vectaraSearchFormRAG');
    if (searchFormRAG) {
        searchFormRAG.addEventListener('submit', async function(e) {
            e.preventDefault();
            const query = document.getElementById('vectara-query-rag').value.trim();
            const resultsDiv = document.getElementById('vectara-search-results-rag');
            if (!query) return;
            resultsDiv.innerHTML = '<div class="text-center">Searching...</div>';
            try {
                const res = await fetch('/vectara/search', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query })
                });
                const data = await res.json();
                if (!res.ok || !data.query || !data.query[0] || !data.query[0].result) {
                    throw new Error(data.detail || 'No results found.');
                }
                const results = data.query[0].result;
                if (!results.length) {
                    resultsDiv.innerHTML = '<div class="alert alert-warning">No relevant reports found.</div>';
                    return;
                }
                let html = '<ul class="list-group">';
                for (const r of results) {
                    html += `<li class="list-group-item">
                        <strong>Score:</strong> ${r.score.toFixed(3)}<br>
                        <strong>Snippet:</strong> <span>${r.text}</span>
                    </li>`;
                }
                html += '</ul>';
                resultsDiv.innerHTML = html;
            } catch (err) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
            }
        });
    }
});
// Download VirusTotal report as text
function downloadVTTextReport() {
    const value = document.getElementById('vt-value').value.trim();
    const typ = document.getElementById('vt-type').value;
    if (!value) {
        alert('Please enter a value (domain, IP, or hash).');
        return;
    }
    const url = `/download_report_text?value=${encodeURIComponent(value)}&typ=${encodeURIComponent(typ)}`;
    window.open(url, '_blank');
}


document.addEventListener('DOMContentLoaded', function() {
    const checkForm = document.getElementById('checkForm');
    if (checkForm) {
        checkForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const type = document.getElementById('inputType').value;
            const value = document.getElementById('inputValue').value.trim();
            if (!value) return;

            // Hide and clear previous enriched results

            const card = document.getElementById('enriched-results-card');
            const claudeSummary = document.getElementById('claude-summary');
            const vtSection = document.getElementById('virustotal-section');
            const vectaraSection = document.getElementById('vectara-section');
            if (card) card.classList.add('d-none');
            if (claudeSummary) claudeSummary.innerHTML = '';
            if (vtSection) vtSection.innerHTML = '';
            if (vectaraSection) vectaraSection.innerHTML = '';
            // Hide old result
            const resultDiv = document.getElementById('result');
            if (resultDiv) resultDiv.innerHTML = '';

            // Show loading state
            if (claudeSummary) claudeSummary.innerHTML = '<span class="text-muted">Loading summary...</span>';
            if (vtSection) vtSection.innerHTML = '<span class="text-muted">Loading VirusTotal data...</span>';
            if (vectaraSection) vectaraSection.innerHTML = '<span class="text-muted">Loading Vectara RAG...</span>';
            if (card) card.classList.remove('d-none');

            // Determine endpoint
            let endpoint = '';
            if (type === 'domain') endpoint = '/research_domain?value=' + encodeURIComponent(value);
            else if (type === 'ip') endpoint = '/research_ip?value=' + encodeURIComponent(value);
            else if (type === 'hash') endpoint = '/research_hash?value=' + encodeURIComponent(value);
            else return;

            try {
                const res = await fetch(endpoint);
                if (!res.ok) throw new Error('Error fetching data');
                const data = await res.json();

                // Claude summary with color highlights for keywords
                if (claudeSummary) {
                    let summary = data.claude_summary || 'No summary available.';
                    // Attempt to extract key findings (simple key: value lines)
                    let findings = [];
                    const lines = summary.split(/\n|<br\s*\/?\s*>/i);
                    for (let line of lines) {
                        let m = line.match(/^\s*([\w\s\-]+):\s*(.+)$/i);
                        if (m) {
                            findings.push({ key: m[1].trim(), value: m[2].trim() });
                        }
                    }
                    if (findings.length > 0) {
                        let table = '<table class="table table-bordered table-sm mb-2"><thead><tr><th>Finding</th><th>Value</th></tr></thead><tbody>';
                        for (const f of findings) {
                            let val = f.value
                                .replace(/malicious/gi, '<span class="badge bg-danger">$&</span>')
                                .replace(/suspicious/gi, '<span class="badge bg-warning text-dark">$&</span>')
                                .replace(/harmless/gi, '<span class="badge bg-success">$&</span>')
                                .replace(/undetected/gi, '<span class="badge bg-secondary">$&</span>');
                            table += `<tr><td>${f.key}</td><td>${val}</td></tr>`;
                        }
                        table += '</tbody></table>';
                        claudeSummary.innerHTML = `<div class="alert alert-info mb-2">${table}</div>`;
                    } else {
                        // Fallback: highlight keywords in summary text
                        summary = summary.replace(/malicious/gi, '<span class="badge bg-danger">$&</span>')
                            .replace(/suspicious/gi, '<span class="badge bg-warning text-dark">$&</span>')
                            .replace(/harmless/gi, '<span class="badge bg-success">$&</span>')
                            .replace(/undetected/gi, '<span class="badge bg-secondary">$&</span>');
                        claudeSummary.innerHTML = `<div class="alert alert-info mb-2"><table class="table table-bordered table-sm mb-0"><tbody><tr><td>${summary}</td></tr></tbody></table></div>`;
                    }
                }

                // VirusTotal section (show key fields with color-coded status)
                if (vtSection) {
                    if (data.virustotal) {
                        let html = '<table class="table table-bordered table-sm mb-2"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>';
                        for (const [k, v] of Object.entries(data.virustotal)) {
            let val = v;
            if (k === 'status' && typeof v === 'string') {
                let badgeClass = 'bg-secondary';
                if (v.toLowerCase() === 'malicious') badgeClass = 'bg-danger';
                else if (v.toLowerCase() === 'suspicious') badgeClass = 'bg-warning text-dark';
                else if (v.toLowerCase() === 'harmless') badgeClass = 'bg-success';
                else if (v.toLowerCase() === 'undetected') badgeClass = 'bg-secondary';
                val = `<span class="badge ${badgeClass}">${v}</span>`;
            } else if (typeof v === 'string') {
                val = v.replace(/malicious/gi, '<span class="badge bg-danger">$&</span>')
                    .replace(/suspicious/gi, '<span class="badge bg-warning text-dark">$&</span>')
                    .replace(/harmless/gi, '<span class="badge bg-success">$&</span>')
                    .replace(/undetected/gi, '<span class="badge bg-secondary">$&</span>');
            } else if (k === 'vendors' && typeof v === 'object' && v !== null) {
                // Render vendors as a table, top 10 by threat
                const threatRank = { malicious: 1, suspicious: 2, harmless: 3, undetected: 4 };
                let vendorArr = Object.entries(v);
                vendorArr.sort((a, b) => {
                    const catA = (a[1].category || '').toLowerCase();
                    const catB = (b[1].category || '').toLowerCase();
                    const rankA = threatRank[catA] || 99;
                    const rankB = threatRank[catB] || 99;
                    if (rankA !== rankB) return rankA - rankB;
                    return a[0].localeCompare(b[0]);
            let val = v;
            if (k === 'status' && typeof v === 'string') {
                let badgeClass = 'bg-secondary';
                if (v.toLowerCase() === 'malicious') badgeClass = 'bg-danger';
                else if (v.toLowerCase() === 'suspicious') badgeClass = 'bg-warning text-dark';
                else if (v.toLowerCase() === 'harmless') badgeClass = 'bg-success';
                else if (v.toLowerCase() === 'undetected') badgeClass = 'bg-secondary';
                val = `<span class=\"badge ${badgeClass}\">${v}</span>`;
            } else if (typeof v === 'string') {
                val = v.replace(/malicious/gi, '<span class=\"badge bg-danger\">$&</span>')
                    .replace(/suspicious/gi, '<span class=\"badge bg-warning text-dark\">$&</span>')
                    .replace(/harmless/gi, '<span class=\"badge bg-success\">$&</span>')
                    .replace(/undetected/gi, '<span class=\"badge bg-secondary\">$&</span>');
            } else if (k === 'vendors' && typeof v === 'object' && v !== null) {
                // Render vendors as a table, top 10 by threat
                const threatRank = { malicious: 1, suspicious: 2, harmless: 3, undetected: 4 };
                let vendorArr = Object.entries(v);
                vendorArr.sort((a, b) => {
                    const catA = (a[1].category || '').toLowerCase();
                    const catB = (b[1].category || '').toLowerCase();
                    const rankA = threatRank[catA] || 99;
                    const rankB = threatRank[catB] || 99;
                    if (rankA !== rankB) return rankA - rankB;
                    return a[0].localeCompare(b[0]);
                });
                const topVendors = vendorArr.slice(0, 10);
                val = '<table class=\"table table-bordered table-sm mb-2\"><thead><tr><th>Vendor</th><th>Result</th><th>Category</th></tr></thead><tbody>';
                for (const [vendor, info] of topVendors) {
                    val += `<tr><td><strong>${vendor}</strong></td><td><span class=\"badge ${badgeClass(info.category)}\">${info.result}</span></td><td>${info.category}</td></tr>`;
                }
                val += '</tbody></table>';
            } else if (k === 'stats' && typeof v === 'object' && v !== null) {
                // Render stats as a table
                val = '<table class=\"table table-bordered table-sm mb-2\"><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>';
                for (const statKey of Object.keys(v)) {
                    let badge = '';
                    if (statKey === 'malicious') badge = 'bg-danger';
                    else if (statKey === 'suspicious') badge = 'bg-warning text-dark';
                    else if (statKey === 'harmless') badge = 'bg-success';
                    else if (statKey === 'undetected') badge = 'bg-secondary';
                    else badge = 'bg-info';
                    val += `<tr><td><span class=\"badge ${badge}\">${statKey}</span></td><td>${v[statKey]}</td></tr>`;
                }
                val += '</tbody></table>';
            } else if (typeof v === 'object') {
                val = `<pre class=\"mb-0\">${JSON.stringify(v, null, 2)}</pre>`;
            }
            html += `<tr><td>${k}</td><td>${val}</td></tr>`;
                    }
                }
            } catch (err) {
                if (claudeSummary) claudeSummary.innerHTML = '<span class="text-danger">Error loading summary.</span>';
                if (vtSection) vtSection.innerHTML = '<span class="text-danger">Error loading VirusTotal data.</span>';
                if (vectaraSection) vectaraSection.innerHTML = '<span class="text-danger">Error loading Vectara data.</span>';
            }
        });
    }
});

function renderResult(data) {
    if (data.error) return `<div class="alert alert-danger">${data.error}</div>`;
    let html = '<div class="card"><div class="card-body">';
    html += `<h5 class="card-title">${data.type.toUpperCase()} Report</h5>`;
    html += `<p><strong>ID:</strong> ${data.id || ''}</p>`;
    if (data.status) html += `<p><strong>Status:</strong> <span class="badge ${badgeClass(data.status)}">${data.status}</span></p>`;
    if (data.reputation !== undefined) html += `<p><strong>Reputation:</strong> ${data.reputation}</p>`;
    if (data.last_analysis_date) {
        const date = new Date(data.last_analysis_date * 1000);
        html += `<p><strong>Last Analysis:</strong> ${date.toLocaleString()}</p>`;
    }
    if (data.stats) {
        html += `<div class="mb-2"><strong>Detection Stats:</strong> `;
        html += `<span class="badge bg-danger">Malicious: ${data.stats.malicious || 0}</span> `;
        html += `<span class="badge bg-warning text-dark">Suspicious: ${data.stats.suspicious || 0}</span> `;
        html += `<span class="badge bg-success">Harmless: ${data.stats.harmless || 0}</span> `;
        html += `<span class="badge bg-secondary">Undetected: ${data.stats.undetected || 0}</span> `;
        html += `</div>`;
        html += `<div class="progress mb-3" style="height: 18px;">
            <div class="progress-bar bg-danger" role="progressbar" style="width: ${(data.stats.malicious/data.total_vendors)*100||0}%" aria-valuenow="${data.stats.malicious}" aria-valuemin="0" aria-valuemax="${data.total_vendors}"></div>
            <div class="progress-bar bg-warning text-dark" role="progressbar" style="width: ${(data.stats.suspicious/data.total_vendors)*100||0}%" aria-valuenow="${data.stats.suspicious}" aria-valuemin="0" aria-valuemax="${data.total_vendors}"></div>
            <div class="progress-bar bg-success" role="progressbar" style="width: ${(data.stats.harmless/data.total_vendors)*100||0}%" aria-valuenow="${data.stats.harmless}" aria-valuemin="0" aria-valuemax="${data.total_vendors}"></div>
        </div>`;
    }
    if (data.vendors) {
        html += '<h6>Vendors <small>(top 10 by threat, click to filter)</small>:</h6>';
        html += '<div class="mb-2">';
        html += `<button class="btn btn-sm btn-danger me-1" onclick="filterVendors('malicious')">Malicious</button>`;
        html += `<button class="btn btn-sm btn-warning me-1" onclick="filterVendors('suspicious')">Suspicious</button>`;
        html += `<button class="btn btn-sm btn-success me-1" onclick="filterVendors('harmless')">Harmless</button>`;
        html += `<button class="btn btn-sm btn-secondary me-1" onclick="filterVendors('undetected')">Undetected</button>`;
        html += `<button class="btn btn-sm btn-outline-dark" onclick="filterVendors('all')">All</button>`;
        html += '</div>';
        // Sort vendors: malicious > suspicious > harmless > undetected > other, then alphabetically
        const threatRank = { malicious: 1, suspicious: 2, harmless: 3, undetected: 4 };
        let vendorArr = Object.entries(data.vendors);
        vendorArr.sort((a, b) => {
            const catA = (a[1].category || '').toLowerCase();
            const catB = (b[1].category || '').toLowerCase();
            const rankA = threatRank[catA] || 99;
            const rankB = threatRank[catB] || 99;
            if (rankA !== rankB) return rankA - rankB;
            return a[0].localeCompare(b[0]);
        });
        // Show only top 10
        const topVendors = vendorArr.slice(0, 10);
        html += '<table class="table table-bordered table-sm mb-2" id="vendors-list"><thead><tr><th>Vendor</th><th>Result</th><th>Category</th></tr></thead><tbody>';
        for (const [vendor, info] of topVendors) {
            html += `<tr data-category="${info.category}"><td><strong>${vendor}</strong></td><td><span class="badge ${badgeClass(info.category)}">${info.result}</span></td><td>${info.category}</td></tr>`;
        }
        html += '</tbody></table>';
    }
    if (data.vt_permalink) {
        html += `<a href="${data.vt_permalink}" class="btn btn-outline-primary mt-2" target="_blank">View Full Report on VirusTotal</a>`;
    }
    if (data.api_info && data.api_info.queries_left !== undefined) {
        html += `<div class="mt-2 text-end"><small>API quota left: <strong>${data.api_info.queries_left}</strong></small></div>`;
    }
    html += `<div class="mt-3"><button class="btn btn-outline-secondary btn-sm" onclick="downloadReport()">Download Report (JSON)</button></div>`;
    html += '</div></div>';
    window.currentVTData = data;
    return html;
}

function badgeClass(status) {
    if (!status) return 'bg-secondary';
    status = status.toLowerCase();
    if (status === 'malicious') return 'bg-danger';
    if (status === 'suspicious') return 'bg-warning text-dark';
    if (status === 'harmless') return 'bg-success';
    if (status === 'undetected') return 'bg-secondary';
    return 'bg-info';
}

function filterVendors(category) {
    const list = document.getElementById('vendors-list');
    if (!list) return;
    for (const li of list.children) {
        if (category === 'all' || li.getAttribute('data-category') === category) {
            li.style.display = '';
        } else {
            li.style.display = 'none';
        }
    }
}

function downloadReport() {
    const data = window.currentVTData;
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `virustotal_report_${data.id || 'result'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
