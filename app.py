#API_KEY = '64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507'
import os
from flask import Flask, request, jsonify, render_template
from flask import Flask, request, render_template, send_file
from flask import Flask, request, render_template, send_file, jsonify
import pandas as pd
import requests
import time

app = Flask(__name__)

API_KEY = '64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507'  # replace with your actual API key

# Function to check the status of an IP address
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
        as_label = data.get('attributes', {}).get('as_owner', 'N/A')  # Extract AS label

        return {
            "ip": id_value,
            "malicious": malicious_value,
            "as_label": as_label
        }
    else:
        return {
            "ip": ip,
            "malicious": "Error",
            "as_label": "N/A"
        }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/estimate_time', methods=['POST'])
def estimate_time():
    file = request.files['file']
    df = pd.read_excel(file)
    ip_addresses = df['IP'].tolist()
    total_ips = len(ip_addresses)

    # Calculate estimated time in seconds
    estimated_time_seconds = total_ips * 15
    estimated_time_minutes = estimated_time_seconds // 60
    remaining_seconds = estimated_time_seconds % 60

    estimated_time_message = f"Estimated time to complete the scan: {estimated_time_minutes} minutes and {remaining_seconds} seconds."

    return jsonify({"estimated_time": estimated_time_message})

@app.route('/scan_ips', methods=['POST'])
def scan_ips():
    file = request.files['file']
    df = pd.read_excel(file)
    ip_addresses = df['IP'].tolist()

    # Start the scanning process
    results = []
    for index, ip in enumerate(ip_addresses):
        result = check_ip(ip)
        results.append(result)
        
        # Respect the API rate limit of 4 requests per minute
        time.sleep(15)  # 15 seconds wait ensures no more than 4 requests per minute

    # Convert results to DataFrame and save to Excel
    results_df = pd.DataFrame(results)
    results_df.to_excel('scan_results.xlsx', index=False)

    return jsonify({"message": "Scan complete. Click below to download the results."})

@app.route('/download')
def download_file():
    return send_file('scan_results.xlsx', as_attachment=True)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
