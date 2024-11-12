import requests
import time
from config import MOBSF_API_URL, MOBSF_API_KEY

# 1. 파일 업로드
def upload_file(filepath):
    url = f"{MOBSF_API_URL}/api/v1/upload"
    headers = {"Authorization": MOBSF_API_KEY}
    files = {"file": open(filepath, "rb")}
    response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        file_hash = response.json().get("hash")
        print(f"파일 업로드 성공: {file_hash}")
        return file_hash
    else:
        print("파일 업로드 실패:", response.text)
        return None