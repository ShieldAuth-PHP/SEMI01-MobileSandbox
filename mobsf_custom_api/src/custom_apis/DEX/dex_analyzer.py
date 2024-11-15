import json
import os
from typing import Dict, List

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder


class MobSFDexAnalyzer:
    def __init__(self, server: str = "http://127.0.0.1:8000", api_key: str = None):
        """MobSF DEX 분석기 초기화"""
        self.server = server
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
    
    def upload_apk(self, file_path: str) -> Dict:
        """APK 파일 업로드"""
        print(f"Uploading {file_path}")
        
        multipart_data = MultipartEncoder(
            fields={'file': (os.path.basename(file_path),
                        open(file_path, 'rb'),
                        'application/octet-stream')}
        )
        
        headers = {
            'Content-Type': multipart_data.content_type,
            'Authorization': self.api_key
        }
        
        response = requests.post(
            f"{self.server}/api/v1/upload",
            data=multipart_data,
            headers=headers
        )
        
        return response.json()
    
    def analyze_dex(self, file_hash: str) -> Dict:
        """DEX 파일 분석"""
        # 소스 코드 가져오기
        headers = {'Authorization': self.api_key}
        response = requests.post(
            f"{self.server}/api/v1/view_source",
            data={"hash": file_hash, "type": "apk", "file": "classes.dex"},
            headers=headers
        )
        dex_info = response.json()
        
        # DEX 파일 암호화 확인
        encrypted_dex = self._check_encryption(dex_info)
        
        return {
            "status": "success",
            "hash": file_hash,
            "dex_analysis": {
                "encrypted": encrypted_dex["is_encrypted"],
                "encryption_type": encrypted_dex.get("encryption_type"),
                "dex_files": encrypted_dex.get("dex_files", [])
            }
        }
    
    def _check_encryption(self, dex_info: Dict) -> Dict:
        """DEX 파일 암호화 여부 확인"""
        dex_files = []
        is_encrypted = False
        encryption_type = None

        # DEX 파일 헤더 분석
        if "dex_files" in dex_info:
            for dex in dex_info["dex_files"]:
                # DEX 헤더 시그니처 확인
                # 정상적인 DEX 파일은 "dex\n035\0" 또는 "dex\n037\0" 시그니처를 가짐
                if not dex["content"].startswith(b"dex\n"):
                    is_encrypted = True
                    # AES-128/ECB 암호화 패턴 확인
                    if self._check_aes_pattern(dex["content"]):
                        encryption_type = "AES-128/ECB"
                    
                dex_files.append({
                    "name": dex["name"],
                    "size": len(dex["content"]),
                    "is_encrypted": is_encrypted,
                    "encryption_type": encryption_type
                })

        return {
            "is_encrypted": is_encrypted,
            "encryption_type": encryption_type,
            "dex_files": dex_files
        }
    
    def _check_aes_pattern(self, content: bytes) -> bool:
        """AES-128/ECB 암호화 패턴 확인"""
        # AES-128/ECB의 일반적인 패턴 확인
        # 1. 블록 크기가 16바이트의 배수
        if len(content) % 16 != 0:
            return False
            
        # 2. 엔트로피 검사
        if self._calculate_entropy(content) > 7.5:  # 높은 엔트로피는 암호화의 특징
            return True
            
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """데이터의 엔트로피 계산"""
        # 바이트 빈도수 계산
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Shannon 엔트로피 계산
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * log2(probability)
            
        return entropy

    def generate_report(self, file_hash: str) -> Dict:
        """분석 보고서 생성"""
        # 기본 JSON 보고서 가져오기
        headers = {'Authorization': self.api_key}
        response = requests.post(
            f"{self.server}/api/v1/report_json",
            data={"hash": file_hash},
            headers=headers
        )
        report_data = response.json()
        
        # DEX 분석 결과 추가
        dex_analysis = self.analyze_dex(file_hash)
        report_data["dex_analysis"] = dex_analysis
        
        return report_data

def main():
    # 설정
    SERVER = "http://127.0.0.1:8000"
    API_KEY = "<API_KEY>"
    APK_PATH = "target.apk"
    
    try:
        # 분석기 초기화
        analyzer = MobSFDexAnalyzer(server=SERVER, api_key=API_KEY)
        
        # 1. APK 업로드
        upload_result = analyzer.upload_apk(APK_PATH)
        file_hash = upload_result["hash"]
        print(f"Uploaded APK. Hash: {file_hash}")
        
        # 2. DEX 분석
        dex_analysis = analyzer.analyze_dex(file_hash)
        print("\nDEX Analysis Results:")
        print(json.dumps(dex_analysis, indent=2))
        
        # 3. 전체 보고서 생성
        report = analyzer.generate_report(file_hash)
        
        # 4. 결과 저장
        with open("dex_analysis_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print("\nReport saved as dex_analysis_report.json")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()