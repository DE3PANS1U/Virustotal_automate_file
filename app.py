import os
from flask import Flask, request, jsonify, render_template
import pandas as pd
import requests
import time

app = Flask(__name__)

API_KEY = '64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507'  # Replace with your actual API key

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        data = response_json.get('data', {})
        id_value = data.get('id', 'N/A')
        malicious_value = data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A')
        as_label = data.get('attributes', {}).get('as_owner', 'N/A')
        
        return {"id": id_value, "malicious": malicious_value, "as_label": as_label}
    else:
        return {"id": ip, "malicious": "Error", "as_label": "N/A"}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan_ips', methods=['POST'])
def scan_ips():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    if file and (file.filename.endswith('.csv') or file.filename.endswith('.xlsx')):
        # Read IP addresses from the uploaded file
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)
        
        # Assume the IP addresses are in the first column
        ip_addresses = df.iloc[:, 0].tolist()
        results = []

        # Rate limiting for the API
        for index, ip in enumerate(ip_addresses):
            result = check_ip(ip)
            results.append(result)
            time.sleep(15)  # To respect the 4 requests per minute rate limit
        
        # Save results to a DataFrame and serve as a downloadable file if needed
        results_df = pd.DataFrame(results)
        results_df.to_excel('scan_results.xlsx', index=False)

        return "Scan complete. Check the 'scan_results.xlsx' file for results.", 200
    else:
        return "Invalid file type. Please upload a CSV or Excel file.", 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
