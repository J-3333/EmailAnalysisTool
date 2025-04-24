Office.onReady((info) => {
  if (info.host === Office.HostType.Outlook) {
    document.getElementById("sideload-msg").style.display = "none";
    document.getElementById("app-body").style.display = "flex";
    document.getElementById("run").onclick = run;
  }
});

export async function run() {
  const item = Office.context.mailbox.item;
  
  // Show loading bar
  document.getElementById("loading-bar").style.display = "block";
  document.getElementById("email-details").innerHTML = "";

 
  const htmlBody = await getHtmlBodyAsync(item);
  const body = normalizeEmailBody(stripHtml(htmlBody)); 
  const urls = extractUrls(htmlBody);                    
  const sender = item.from ? item.from.emailAddress : "Unknown Sender";
  const subject = item.subject;
  const headers = await getHeadersAsync(item);
  const authResults = extractImportantHeaders(headers);

  console.log("Extracted Authentication Results", authResults)

  //Payload for backend
  const payload = {
    sender_domain: sender.split("@")[1], 
    subject: subject,
    body: body,
    url_count: urls.length,
    urls: urls,
    spf: authResults.spf,
    dkim: authResults.dkim,
    dmarc: authResults.dmarc
  };

  console.log("Payload sent to backend:", JSON.stringify(payload, null, 2));

  // Send data to the backend for analysis
  try {
    const backendUrl = "http://localhost:5000/analyze-email";
    const response = await fetch(backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      console.error("Server Error:", response.statusText);
      document.getElementById("email-details").innerHTML = `<b>Error analyzing email. Server error.</b>`;
      return;
    }

    const result = await response.json();
    console.log("Response from backend:", result);

    if (!result.label || result.confidence === undefined) {
      console.error("Unexpected Response Format:", result);
      document.getElementById("email-details").innerHTML = `<b>Error analyzing email. Unexpected response format.</b>`;
      return;
    }
    
    // Display results
    const container = document.getElementById("email-details");
    const label = result.label.toLowerCase();
    container.innerHTML = `
      ${createPredictionBanner(label, result.confidence)}
      ${createClassificationSection(label, result.confidence)}
      ${createAuthenticationSection(authResults, result.auth_status)}
      ${createLinkAnalysisSection(result.link_analysis)}
      ${createExportSection()}
    `;

    // Add export function to window object so it can be called from HTML
    window.exportResults = function(results) {
      const dataStr = JSON.stringify(results, null, 2);
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
      
      const exportFileDefaultName = 'email-analysis-results.json';
      
      const linkElement = document.createElement('a');
      linkElement.setAttribute('href', dataUri);
      linkElement.setAttribute('download', exportFileDefaultName);
      linkElement.click();
    };

    // Add click event listener to the export button
    document.getElementById('export-btn').addEventListener('click', () => {
      window.exportResults(result);
    });
  } catch(error) {
    console.error("Error:", error);
    document.getElementById("email-details").innerHTML = `<b>Error analyzing email. Please try again.</b>`;
  } finally {
    // Hide loading bar
    document.getElementById("loading-bar").style.display = "none";
  }
}


function getBodyAsync(item) {
  return new Promise((resolve) => {
    item.body.getAsync(Office.CoercionType.Html, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        const cleanText = stripHtml(result.value);         
        resolve(normalizeEmailBody(cleanText));            
      } else {
        resolve("Failed to retrieve body.");
      }
    });
  });
}


function normalizeEmailBody(text) {
  return text
    .replace(/\r\n/g, '\n')
    .replace(/\n\s*\n/g, '\n\n')      
    .replace(/\t+/g, ' ')             
    .replace(/ +/g, ' ')            
    .replace(/\n{3,}/g, '\n\n')       
    .trim();
}


const WHITELIST_DOMAINS = [
  /^www\.w3\.org$/,
  /^ci\d+\.googleusercontent\.com$/, 
  /^fonts\.googleapis\.com$/,
  /^fonts\.gstatic\.com$/,
  /^schemas\.microsoft\.com$/,
  /^use\.typekit\.net$/,
  /^cdnjs\.cloudflare\.com$/,
  /^static\.xx\.fbcdn\.net$/,
  /^www\.facebook\.com$/,
  /^www\.instagram\.com$/,
  /^www\.linkedin\.com$/,
  /^www\.gstatic\.com$/,
  /^www\.mandrillapp\.com$/,
];


function extractUrls(text) {
  const urlRegex = /(https?:\/\/[^\s"<>\)]+)/g;
  let urls = text.match(urlRegex) || [];

  let uniqueDomains = new Set();

  // Process each URL
  urls.forEach(url => {
    try {
      // Extract main domain
      const mainDomain = new URL(url).hostname.toLowerCase();
      uniqueDomains.add(mainDomain);

      // Extract domains from query parameters
      const params = new URL(url).searchParams;
      for (const [param, value] of params.entries()) {
        // Check if parameter might contain a URL
        if (param.toLowerCase().includes('url') || 
            param.toLowerCase().includes('link') || 
            param.toLowerCase().includes('redirect')) {
          try {
            // Try to decode URL-encoded value
            const decodedValue = decodeURIComponent(value);
            // Check if decoded value is a URL
            if (decodedValue.startsWith('http://') || decodedValue.startsWith('https://')) {
              const paramDomain = new URL(decodedValue).hostname.toLowerCase();
              uniqueDomains.add(paramDomain);
            }
          } catch (e) {
            // If URL decoding fails, try to find domains in the raw value
            const domainMatch = value.match(/(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/);
            if (domainMatch) {
              uniqueDomains.add(domainMatch[1].toLowerCase());
            }
          }
        }
      }
    } catch (error) {
      console.error("Error processing URL:", url, error);
    }
  });

  // Exclude common safe infrastructure domains
  const filtered = Array.from(uniqueDomains).filter(domain => {
    return !WHITELIST_DOMAINS.some(pattern => pattern.test(domain));
  });

  return filtered;
}


function getHeadersAsync(item) {
  return new Promise((resolve) => {
    item.getAllInternetHeadersAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value);
      } else {
        resolve("");
      }
    });
  });
}


function extractImportantHeaders(headers) {
  return {
      "spf": parseSPF(headers),
      "dkim": parseDKIM(headers),
      "dmarc": parseDMARC(headers),
  };
}

// Extract SPF, DKIM, and DMARC results
function parseSPF(headers) {
  let match = headers.match(/Received-SPF:\s*(pass|fail|none|softfail)/i);
  return match ? match[1].toUpperCase() : "NONE";
}

function parseDKIM(headers) {
  let match = headers.match(/dkim=(pass|fail|none)/i);
  return match ? match[1].toUpperCase() : "NONE";
}

function parseDMARC(headers) {
  let match = headers.match(/dmarc=(pass|fail|none)/i);
  return match ? match[1].toUpperCase() : "NONE";
}

// Template functions for HTML generation
function createPredictionBanner(label, confidence) {
  return `
    <div class="prediction-banner" data-type="${label === 'legitimate' ? 'safe' : label}">
      <div class="prediction-text" data-type="${label === 'legitimate' ? 'safe' : label}">
        ${label === 'phishing' ? '⚠️ Phishing Email' : 
          label === 'spam' ? '📧 Spam Email' : 
          '✅ Safe Email'}
      </div>
      <div class="confidence-badge">${confidence}% Confidence</div>
    </div>
  `;
}

function createClassificationSection(label, confidence) {
  return `
    <div class="result-section">
      <div class="result-title">📝 Email Classification</div>
      <div class="result-item">
        <span class="result-label">Type:</span>
        <span class="result-value">${label.charAt(0).toUpperCase() + label.slice(1)}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Confidence:</span>
        <span class="result-value">${confidence}%</span>
      </div>
    </div>
  `;
}

function createAuthenticationSection(authResults, authStatus) {
  return `
    <div class="result-section">
      <div class="result-title">🔒 Email Authentication</div>
      <div class="result-item">
        <span class="result-label">SPF:</span>
        <span class="result-value">${authResults.spf}</span>
      </div>
      <div class="result-item">
        <span class="result-label">DKIM:</span>
        <span class="result-value">${authResults.dkim}</span>
      </div>
      <div class="result-item">
        <span class="result-label">DMARC:</span>
        <span class="result-value">${authResults.dmarc}</span>
      </div>
      <div class="result-item">
        <span class="result-label">Status:</span>
        <span class="result-value">${authStatus}</span>
      </div>
    </div>
  `;
}

function createLinkAnalysisSection(linkAnalysis) {
  if (!linkAnalysis || linkAnalysis.length === 0) {
    return `
      <div class="result-section">
        <div class="result-title">🔗 Link Analysis</div>
        <div class="result-item"><span class="result-value">No URLs found in the email.</span></div>
      </div>
    `;
  }

  const linkAnalysisHTML = linkAnalysis.map((link, index) => {
    // Handle API failure case
    if (link.status === "api_failed") {
      return `
        <div class="domain-analysis">
          <div class="result-item">
            <span class="result-label">Domain:</span>
            <span class="result-value">${link.domain}</span>
          </div>
          <div class="result-item">
            <span class="result-value api-error">${link.message}</span>
          </div>
          ${index < linkAnalysis.length - 1 ? '<div class="domain-separator"></div>' : ''}
        </div>
      `;
    }

    const domain = link.domain || "N/A";
    const maliciousCount = link.malicious_count ?? "N/A";
    const domainAge = link.domain_age ?? "N/A";
    const riskScore = link.risk_score ?? "N/A";
    const statusClass = riskScore >= 10 ? 'status-high-risk' :
                      riskScore >= 5 ? 'status-suspicious' :
                      'status-safe';
    const statusIcon = riskScore >= 10 ? '⚠️' :
                     riskScore >= 5 ? '⚠️' :
                     '✅';
    const statusText = riskScore >= 10 ? 'High Risk' :
                     riskScore >= 5 ? 'Suspicious' :
                     'Safe';

    return `
      <div class="domain-analysis">
        <div class="result-item">
          <span class="result-label">Domain:</span>
          <span class="result-value">${domain}</span>
        </div>
        <div class="result-item">
          <span class="result-label">Risk Status:</span>
          <span class="status-indicator ${statusClass}">
            ${statusIcon} ${statusText}
          </span>
        </div>
        <div class="result-item">
          <span class="result-label">Risk Score:</span>
          <span class="result-value">${riskScore}</span>
        </div>
        <div class="result-item">
          <span class="result-label">Malicious Count:</span>
          <span class="result-value">${maliciousCount}</span>
        </div>
        <div class="result-item">
          <span class="result-label">Domain Age:</span>
          <span class="result-value">${domainAge} days</span>
        </div>
        ${link.warning ? `
          <div class="result-item">
            <span class="result-label">Warning:</span>
            <span class="result-value warning-icon">⚠️ ${link.warning}</span>
          </div>
        ` : ''}
        ${index < linkAnalysis.length - 1 ? '<div class="domain-separator"></div>' : ''}
      </div>
    `;
  }).join('');

  return `
    <div class="result-section">
      <div class="result-title">🔗 Link Analysis</div>
      ${linkAnalysisHTML}
    </div>
  `;
}

function createExportSection() {
  return `
    <div class="export-section">
      <button id="export-btn" class="export-button">
        📥 Export Analysis Results
      </button>
    </div>
  `;
}

function stripHtml(html) {
  const tempDiv = document.createElement("div");
  tempDiv.innerHTML = html;

  // Remove script, style, and noscript tags entirely
  const tagsToRemove = tempDiv.querySelectorAll("script, style, noscript, iframe, head");
  tagsToRemove.forEach(el => el.remove());

  const wrappers = tempDiv.querySelectorAll("table, div, span");
  wrappers.forEach(el => {
    if (el.children.length === 1 && el.textContent.trim() === el.children[0].textContent.trim()) {
      el.replaceWith(...el.childNodes);
    }
  });

  
  return tempDiv.textContent || tempDiv.innerText || "";
}


function getHtmlBodyAsync(item) {
  return new Promise((resolve) => {
    item.body.getAsync(Office.CoercionType.Html, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value);
      } else {
        resolve(""); 
      }
    });
  });
}

