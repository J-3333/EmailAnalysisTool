Office.onReady((info) => {
    if (info.host === Office.HostType.Outlook) {
        document.getElementById("sideload-msg").style.display = "none";
        document.getElementById("app-body").style.display = "flex";
        document.getElementById("extract-button").onclick = extractEmailDetails;
    }
});

async function extractEmailDetails() {
    const item = Office.context.mailbox.item;
    
    // Show loading bar
    document.getElementById("loading-bar").style.display = "block";
    document.getElementById("email-details").innerHTML = "";

    //Extract from email fields
    const sender = item.from ? item.from.emailAddress : "Unknown Sender";
    const subject = item.subject;
    const body = await getBodyAsync(item);
    const urls = extractUrls(body);

    //Extract email headers
    const headers = await getHeadersAsync(item);
    const authResults = extractImportantHeaders(headers);

    //Payload for backend
    const payload = {
        sender: sender,
        subject: subject,
        body: body,
        urls: urls,
        spf: authResults.spf,
        dkim: authResults.dkim,
        dmarc: authResults.dmarc
    };

    try {
        const backendUrl = "http://localhost:5001/analyze-perplexity";
        const response = await fetch(backendUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`Server Error: ${response.statusText}`);
        }

        const result = await response.json();

        // Display results
        const container = document.getElementById("email-details");
        container.innerHTML = `
            <div class="result-section">
                <div class="result-title">🤖 Perplexity Analysis</div>
                <div class="result-item">
                    <span class="result-label">Result:</span>
                    <span class="result-value">
                        <strong>${result.classification.replace(':', '')}</strong>
                    </span>
                </div>
                <div class="result-item">
                    <span class="result-label">Explanation:</span>
                    <span class="result-value">${result.explanation || 'No explanation available'}</span>
                </div>
            </div>

            <div class="result-section">
                <div class="result-title">📧 Email Context</div>
                <div class="result-item">
                    <span class="result-label">From:</span>
                    <span class="result-value">${sender}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Subject:</span>
                    <span class="result-value">${subject}</span>
                </div>
            </div>

            ${urls.length > 0 ? `
                <div class="result-section">
                    <div class="result-title">🔗 Links Found</div>
                    <div class="result-item">
                        <span class="result-value">${urls.length} unique domain${urls.length !== 1 ? 's' : ''} detected</span>
                    </div>
                </div>
            ` : ''}
        `;
    } catch(error) {
        console.error("Error:", error);
        document.getElementById("email-details").innerHTML = `<b>Error analyzing email. Please try again.</b>`;
    } finally {
        // Hide loading bar
        document.getElementById("loading-bar").style.display = "none";
    }
}

// Helper functions
function getBodyAsync(item) {
    return new Promise((resolve) => {
        item.body.getAsync(Office.CoercionType.Text, (result) => {
            if (result.status === Office.AsyncResultStatus.Succeeded) {
                resolve(result.value);
            } else {
                resolve("Failed to retrieve body.");
            }
        });
    });
}

function extractUrls(text) {
    const urlRegex = /(https?:\/\/[^\s"<>\)]+)/g;
    let urls = text.match(urlRegex) || []; 

    // Normalize URLs by removing trailing slashes
    let uniqueUrls = [...new Set(urls.map(url => url.replace(/\/+$/, '')))];

    // Extract only the domain (without path/query params)
    let domains = uniqueUrls.map(url => {
        try {
            return new URL(url).hostname;
        } catch (error) {
            return url;
        }
    });

    return [...new Set(domains)];
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