from flask import Flask, request, jsonify
import requests
import os
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app)

# Load Perplexity API Key from environment variable
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY")

if not PERPLEXITY_API_KEY:
    print("Error: Perplexity API key not found in environment variables.")

# Perplexity API URL
PERPLEXITY_URL = "https://api.perplexity.ai/chat/completions"

@app.route('/analyze-perplexity', methods=['POST'])
def analyze_perplexity():
    #start_time = time.time() - Performance Testing
    try:
        # Extract JSON data from the request
        data = request.get_json()
        print("Received Payload for Perplexity:", data)

        # Extract email details
        subject = data.get("subject", "")
        body = data.get("body", "")
        sender = data.get("sender", "unknown")
        urls = data.get("urls", [])
        spf_result = data.get("spf", "Unknown")
        dkim_result = data.get("dkim", "Unknown")
        dmarc_result = data.get("dmarc", "Unknown")

        # Construct the user query for Perplexity
        user_query = f"""
        Analyze the following email and classify it as Phishing, Spam, or Legitimate.
        Provide a concise explanation for your classification.

        **Subject:** {subject}
        **Body:** {body}
        **Sender:** {sender}
        **URLs:** {', '.join(urls) if urls else 'None'}
        **SPF Result:** {spf_result}
        **DKIM Result:** {dkim_result}
        **DMARC Result:** {dmarc_result}
        """

        # Define Perplexity API request payload
        payload = {
            "model": "sonar",
            "messages": [
                {"role": "system", "content": "Respond in the shortest possible way. Only return classification and a brief reason. No citations required."},
                {"role": "user", "content": f"Classify this email as Phishing, Spam, or Legitimate with brief explanation: "
                                             f"Subject: {subject}, Body: {body}, Sender: {sender}, URLs: {', '.join(urls) if urls else 'None'}, "
                                             f"SPF: {spf_result}, DKIM: {dkim_result}, DMARC: {dmarc_result}."}
            ],
            "max_tokens": 150, 
            "temperature": 0.3,
            "top_p": 0.9,
            "top_k": 5,
            "stream": False,
            "presence_penalty": 0,
            "frequency_penalty": 1,
            "response_format": None
        }

        # Define request headers
        headers = {
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json"
        }
        


        # Send request to Perplexity API
        response = requests.post(PERPLEXITY_URL, json=payload, headers=headers)

        if response.status_code == 200:
            response_data = response.json()
            print("Perplexity API Response:", response_data)

            # Extract classification and reasoning from response
            classification_response = response_data.get("choices", [{}])[0].get("message", {}).get("content", "Unknown")
            
            # Remove markdown formatting and split by newlines
            clean_response = classification_response.replace('**', '').strip()
            parts = clean_response.split('\n\n')
            
            if len(parts) >= 2:
                # First part is the classification
                classification = parts[0].strip()
                # Second part is the explanation, remove "Reason:" if present
                explanation = parts[1].strip().replace('Reason:', '').strip()
            else:
                # If no clear separation, try to get first word as classification
                words = clean_response.strip().split()
                classification = words[0] if words else "Unknown"
                explanation = " ".join(words[1:]).replace('Reason:', '').strip() if len(words) > 1 else ""

            # Structure the response
            result = {
                "classification": classification,
                "explanation": explanation,
                "raw_response": response_data  # Full API response for debugging
            }

            print("Sending response:", result)  # Debug print
            #elapsed_time = round(time.time() - start_time, 2) - Performance Testing
            #print(f"Total Perplexity analysis time: {elapsed_time} seconds") - Performance Testing
            return jsonify(result)
        else:
            print(f"Error from Perplexity API: {response.status_code} - {response.text}")
            return jsonify({"error": "Failed to analyze email using Perplexity"}), 500

    except Exception as e:
        print("Backend Error:", str(e))
        return jsonify({"error": f"Something went wrong: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)  
