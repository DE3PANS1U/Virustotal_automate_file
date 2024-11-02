#API_KEY = '64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507'
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
            "id": id_value,
            "malicious": malicious_value,
            "as_label": as_label
        }
    else:
        return {
            "id": ip,
            "malicious": "Error",
            "as_label": "N/A"
        }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan_ips', methods=['POST'])
def scan_ips():
    # Check if a file was uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']

    # Check if the file is empty or invalid
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
        # Read the uploaded Excel file
        df = pd.read_excel(file)
        ips = df['IP'].tolist()
        total_ips = len(ips)

        # Calculate estimated time based on 15 seconds per IP
        total_seconds = total_ips * 15
        estimated_minutes = total_seconds // 60
        estimated_seconds = total_seconds % 60

        # Dummy scan logic for demonstration
        scan_results = [{"IP": ip, "Status": "Clean" if i % 2 == 0 else "Infected"} for i, ip in enumerate(ips)]

        # Convert results to DataFrame and save to Excel
        results_df = pd.DataFrame(scan_results)
        results_file = 'scan_results.xlsx'
        results_df.to_excel(results_file, index=False)

        # Return a success message with estimated time in minutes and seconds
        return jsonify({
            "message": "Scan complete! Click the button to download the results.",
            "estimated_time": f"{estimated_minutes} minutes and {estimated_seconds} seconds"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download')
def download_file():
    path = "scan_results.xlsx"
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    else:
        return "No file found to download", 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
