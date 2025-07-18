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
document.getElementById('checkForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const type = document.getElementById('inputType').value;
    const value = document.getElementById('inputValue').value.trim();
    let endpoint = '';
    if (type === 'domain') endpoint = '/research_domain';
    else if (type === 'ip') endpoint = '/research_ip';
    else if (type === 'hash') endpoint = '/research_hash';
    else return;
    document.getElementById('result').innerHTML = '<div class="text-center">Checking...</div>';
    try {
        const res = await fetch(`${endpoint}?value=${encodeURIComponent(value)}`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Error');
        document.getElementById('result').innerHTML = renderResult(data);
    } catch (err) {
        document.getElementById('result').innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
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
        html += '<h6>Vendors <small>(click to filter)</small>:</h6>';
        html += '<div class="mb-2">';
        html += `<button class="btn btn-sm btn-danger me-1" onclick="filterVendors('malicious')">Malicious</button>`;
        html += `<button class="btn btn-sm btn-warning me-1" onclick="filterVendors('suspicious')">Suspicious</button>`;
        html += `<button class="btn btn-sm btn-success me-1" onclick="filterVendors('harmless')">Harmless</button>`;
        html += `<button class="btn btn-sm btn-secondary me-1" onclick="filterVendors('undetected')">Undetected</button>`;
        html += `<button class="btn btn-sm btn-outline-dark" onclick="filterVendors('all')">All</button>`;
        html += '</div>';
        html += '<ul id="vendors-list">';
        for (const [vendor, info] of Object.entries(data.vendors)) {
            html += `<li data-category="${info.category}"><strong>${vendor}:</strong> <span class="badge ${badgeClass(info.category)}">${info.result}</span> <span class="text-muted small">(${info.category})</span></li>`;
        }
        html += '</ul>';
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
