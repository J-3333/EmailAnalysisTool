from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
from transformers import BertTokenizer, BertModel
import torch
import pandas as pd
import requests
import time
import os
from urllib.parse import urlparse
import asyncio
import aiohttp


app = Flask(__name__)
CORS(app)

# Load the trained model and preprocessors
hybrid_model = joblib.load("hybrid_model.pkl")
scaler = joblib.load("scaler.pkl")
encoder = joblib.load("encoder.pkl")

# Load BERT tokenizer and model
tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
bert_model = BertModel.from_pretrained("bert-base-uncased")
bert_model.eval()  # Set model to evaluation mode

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
if VIRUSTOTAL_API_KEY is None:
    print("Error: VirusTotal API key not found in environment variables.")
else:
    print("API key found!")

# Function to generate BERT embeddings
def get_bert_embeddings(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        outputs = bert_model(**inputs)
    return outputs.last_hidden_state.mean(dim=1).numpy()

# Function to check URL reputation using VirusTotal
async def check_url_virustotal_async(session, url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    try:
        # Submit URL for scanning
        print(f"Submitting URL to VirusTotal: {url}")
        async with session.post(api_url, headers=headers, data=data) as response:
            if response.status == 200:
                analysis_id = (await response.json())["data"]["id"]
                result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                
                while True:
                    async with session.get(result_url, headers=headers) as result_response:
                        if result_response.status == 200:
                            result_data = await result_response.json()
                            status = result_data["data"]["attributes"]["status"]
                            if status == "completed":
                                print(f"Analysis completed for URL: {url}")
                                return result_data
                            else:
                                print(f"Waiting for analysis to complete... Retrying...")
                                await asyncio.sleep(5)
                        else:
                            print(f"Error fetching analysis status: {result_response.status}")
                            return None
            else:
                print(f"Error submitting URL for analysis: {response.status}")
                return None
    except Exception as e:
        print(f"Error checking URL {url}: {str(e)}")
        return None

async def analyze_urls_concurrently(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [check_url_virustotal_async(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
        return results

async def get_domain_registration_date_async(session, domain):
    WHOIS_API_KEY = os.getenv('WHOIS_API_KEY')  
    if WHOIS_API_KEY is None:
        print(f"Error: WHOIS API key not found in environment variables for domain: {domain}")
        return "N/A"

    api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=json"
    print(f"Making WHOIS request for domain: {domain}")

    try:
        async with session.get(api_url) as response:
            response_text = await response.text()
            print(f"WHOIS API Response Status: {response.status}")
            
            if response.status == 401:
                print(f"WHOIS API subscription limit reached for domain: {domain}")
                return "N/A"
            
            if response.status == 200:
                try:
                    whois_data = await response.json()
                    domain_age_days = whois_data.get("WhoisRecord", {}).get("estimatedDomainAge", "N/A")
                    print(f"Successfully extracted Domain Age for {domain}: {domain_age_days} days")
                    return domain_age_days
                except Exception as json_error:
                    print(f"Error parsing WHOIS JSON response for {domain}: {str(json_error)}")
                    return "N/A"
            else:
                print(f"WHOIS API Error for {domain}: Status {response.status}")
                return "N/A"
    except Exception as e:
        print(f"Error fetching WHOIS data for {domain}: {str(e)}")
        return "N/A"

async def analyze_domains_concurrently(domains):
    async with aiohttp.ClientSession() as session:
        # Run VirusTotal and WHOIS analysis concurrently
        virus_total_tasks = [check_url_virustotal_async(session, domain) for domain in domains]
        whois_tasks = [get_domain_registration_date_async(session, domain) for domain in domains]
        
        try:
            virus_total_results, whois_results = await asyncio.gather(
                asyncio.gather(*virus_total_tasks),
                asyncio.gather(*whois_tasks)
            )
            return virus_total_results, whois_results
        except Exception as e:
            print(f"Error in concurrent analysis: {str(e)}")
            # Return empty results in case of error
            return [None] * len(domains), ["Error in analysis"] * len(domains)

# Function to parse VirusTotal response
def parse_virustotal_response(response):
    if response is None:
        return {"status": "unknown", "malicious_count": None}
    
    stats = response["data"]["attributes"]["stats"]
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    
    if malicious_count > 0 or suspicious_count > 0:
        return {"status": "suspicious", "malicious_count": malicious_count}
    else:
        return {"status": "safe", "malicious_count": malicious_count}

PHISHING_SCORE_THRESHOLD = 8  # Flag as phishing if total risk score >= 8
SUSPICIOUS_SCORE_THRESHOLD = 5  # Flag as suspicious if total risk score is between 5-9

def calculate_risk_score(malicious_count, domain_age):
    """Assigns a risk score based on VirusTotal detections and WHOIS domain age."""
    # If VirusTotal analysis failed, return 0 (unknown status)
    if malicious_count is None:
        return 0

    # VirusTotal Score Mapping
    vt_score_map = {1: 2, 2: 4, 3: 6}
    virus_total_score = vt_score_map.get(malicious_count, 8 if malicious_count >= 4 else 0)
    
    # If WHOIS data is unavailable, rely solely on VirusTotal score
    if isinstance(domain_age, str) and "Error" in domain_age:
        print(f"WHOIS data unavailable, using VirusTotal score only: {virus_total_score}")
        return virus_total_score

    try:
        domain_age = int(domain_age)
    except (ValueError, TypeError):
        print(f"Invalid domain age format, using VirusTotal score only: {virus_total_score}")
        return virus_total_score

    # Domain Age Score Mapping
    if domain_age is None:
        domain_age_score = 0  # Default to no risk if WHOIS fails
    elif domain_age < 7:
        domain_age_score = 7  # High risk
    elif domain_age < 30:
        domain_age_score = 5  # Moderate risk
    elif domain_age < 180:
        domain_age_score = 3  # Low risk
    else:
        domain_age_score = 0  # Very low risk

    # Total Risk Score
    total_risk_score = virus_total_score + domain_age_score
    return total_risk_score


# Function to analyze links in an email
def analyze_email_links(urls):
    """Analyzes URLs using VirusTotal and WHOIS to assign a combined risk score."""
    results = []
    analyzed_domains = {}  # To avoid duplicate lookups

    # Extract unique domains to avoid duplicate lookups
    unique_domains = set()
    domain_to_urls = {}
    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else url
        unique_domains.add(domain)
        if domain not in domain_to_urls:
            domain_to_urls[domain] = []
        domain_to_urls[domain].append(url)

    # Run concurrent analysis for unique domains
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    virus_total_results, whois_results = loop.run_until_complete(analyze_domains_concurrently(list(unique_domains)))
    loop.close()

    # Process results
    for domain, virus_total_result, domain_age in zip(unique_domains, virus_total_results, whois_results):
        print(f"Analyzing Domain: {domain}")

        # Check if VirusTotal API failed
        if virus_total_result is None:
            # Return special status for API failure
            for url in domain_to_urls[domain]:
                results.append({
                    "url": url,
                    "domain": domain,
                    "status": "api_failed",
                    "message": "Link Analysis not available"
                })
            continue

        # Parse VirusTotal response
        analysis = parse_virustotal_response(virus_total_result)
        malicious_count = analysis.get("malicious_count")

        # Handle WHOIS failures
        if isinstance(domain_age, str) and "Error" in domain_age:
            domain_age = "N/A"

        # Calculate Risk Score
        total_risk_score = calculate_risk_score(malicious_count, domain_age)

        # Store results for this domain
        analyzed_domains[domain] = {
            "domain": domain,
            "domain_age": domain_age,
            "malicious_count": malicious_count,
            "risk_score": total_risk_score,
            "analysis": analysis
        }

        # Add results for all URLs associated with this domain
        for url in domain_to_urls[domain]:
            results.append({
                "url": url,
                **analyzed_domains[domain]
            })

    return results


#Function to check email auth
def get_authentication_status(spf, dkim, dmarc):
    spf = spf.lower()
    dkim = dkim.lower()
    dmarc = dmarc.lower()

    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        return "Email is authenticated (Safe)"
    
    elif spf == "fail" or dkim == "fail" or dmarc == "fail":
        return "Email failed authentication (Potentially Suspicious)"

    elif spf == "none" or dkim == "none" or dmarc == "none":
        return "Email authentication is not found"

    else:
        return "Unknown authentication status (Check Headers Manually)"

@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    try:
        # Extract JSON data
        data = request.get_json()
        print("Received Payload:", data)
        
        # Extract email data
        subject = data.get("subject", "")
        body = data.get("body", "")
        url_count = data.get("url_count", 0)
        sender_domain = data.get("sender_domain", "unknown")
        urls = data.get("urls", [])
        
        # Extract authentication results
        spf = data.get("spf", "NONE")
        dkim = data.get("dkim", "NONE")
        dmarc = data.get("dmarc", "NONE")
        auth_status = get_authentication_status(spf, dkim, dmarc)
        
        # Generate BERT embeddings
        subject_embedding = get_bert_embeddings(subject).flatten()
        body_embedding = get_bert_embeddings(body).flatten()

        # Preprocess numerical and categorical features
        url_count_df = pd.DataFrame([[url_count]], columns=["url_count"])
        sender_domain_df = pd.DataFrame([[sender_domain]], columns=["sender_domain"])

        # Apply transformations
        scaled_url_count = scaler.transform(url_count_df)
        encoded_sender_domain = encoder.transform(sender_domain_df).toarray()

        # Combine all features into a single feature vector
        feature_vector = np.hstack([
            subject_embedding,
            body_embedding,
            scaled_url_count.flatten(),
            encoded_sender_domain.flatten()
        ])

        # Make prediction
        prediction = hybrid_model.predict([feature_vector])[0]
        confidence = hybrid_model.predict_proba([feature_vector])[0].max()
        label = "Phishing" if prediction == 2 else "Spam" if prediction == 1 else "Legitimate"

        # Try to analyze links, but handle API failures gracefully
        try:
            link_analysis_results = analyze_email_links(urls) if urls else []
        except Exception as e:
            print(f"Error in link analysis: {str(e)}")
            link_analysis_results = [{
                "url": url,
                "domain": urlparse(url).netloc if urlparse(url).netloc else url,
                "status": "api_failed",
                "message": "Link Analysis not available"
            } for url in urls]

        # Check link analysis results and override classification if needed
        if link_analysis_results:
            # Check if any link has a high risk score or is suspicious
            for link in link_analysis_results:
                risk_score = link.get("risk_score", 0)
                if risk_score >= PHISHING_SCORE_THRESHOLD:
                    label = "Phishing"
                    confidence_boost = min(0.7 + (risk_score - PHISHING_SCORE_THRESHOLD) * 0.05, 0.95)
                    confidence = max(confidence, confidence_boost)
                    break
                elif risk_score >= SUSPICIOUS_SCORE_THRESHOLD:
                    label = "Phishing"  # Override to phishing if suspicious
                    confidence_boost = min(0.6 + (risk_score - SUSPICIOUS_SCORE_THRESHOLD) * 0.05, 0.85)
                    confidence = max(confidence, confidence_boost)
                    break

        # Prepare and return response
        response_data = {
            "label": label,
            "confidence": round(confidence * 100, 2),
            "auth_status": auth_status,
            "link_analysis": link_analysis_results
        }

        print("Sending Response:", response_data)
        return jsonify(response_data)

    except Exception as e:
        print("Backend Error:", str(e))
        return jsonify({"error": f"Something went wrong: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
