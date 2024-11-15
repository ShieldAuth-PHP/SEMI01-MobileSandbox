import sys
import os
import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

SERVER = "http://127.0.0.1:8000"
APIKEY = 'API Key'

#업로드 파일
def upload(file_path):
    print("Uploading file:", file_path)
    multipart_data = MultipartEncoder(
        fields={
            'file': (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')
        }
    )
    headers = {
        'Content-Type': multipart_data.content_type,
        'Authorization': APIKEY
    }
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    print("Upload response:", response.text)
    if response.status_code != 200:
        raise Exception(f"Failed to upload file: {response.text}")
    return response.json()

#스캔 파일
def scan(file_hash):
    print("Scanning file with hash:", file_hash)
    headers = {'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/scan', data={'hash': file_hash}, headers=headers)
    print("Scan response:", response.text)
    if response.status_code != 200:
        raise Exception(f"Failed to scan file: {response.text}")
    return response.json()

#스코어보드
def get_scorecard(file_hash):
    print("Fetching scorecard for hash:", file_hash)
    headers = {'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/scorecard', data={'hash': file_hash}, headers=headers)
    print("Scorecard response:", response.text)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch scorecard: {response.text}")
    return response.json()

#PDF 생성
def generate_pdf(file_hash):
    print("Generating PDF report for hash:", file_hash)
    headers = {'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/download_pdf', data={'hash': file_hash}, headers=headers, stream=True)
    if response.status_code != 200:
        raise Exception(f"Failed to generate PDF report: {response.text}")
    with open("report.pdf", 'wb') as report_file:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                report_file.write(chunk)
    print("Report saved as report.pdf")

def main(apk_file_path):
    if not os.path.isfile(apk_file_path) or not apk_file_path.endswith(".apk"):
        print("Invalid APK file:", apk_file_path)
        sys.exit(1)
    
    # Upload the APK
    upload_response = upload(apk_file_path)
    if 'hash' not in upload_response:
        print("Failed to upload the APK file.")
        sys.exit(1)
    
    file_hash = upload_response['hash']
    
    scan_response = scan(file_hash)
    
    scorecard_response = get_scorecard(file_hash)
    print("App Security Scorecard:", json.dumps(scorecard_response, indent=4))

    generate_pdf(file_hash)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <apk_file>")
        sys.exit(1)
    apk_file_path = sys.argv[1]
    main(apk_file_path)
