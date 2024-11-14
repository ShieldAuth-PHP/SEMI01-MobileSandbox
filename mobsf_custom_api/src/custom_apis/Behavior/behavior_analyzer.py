import json
from datetime import datetime
from typing import Dict, List, Optional

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder


class MobSFBehaviorAnalyzer:
    def __init__(self, server: str = "http://127.0.0.1:8000", api_key: str = None):
        self.server = server
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        
    def analyze_app_behavior(self, file_hash: str) -> Dict:
        """앱 행위 분석"""
        try:
            # 정적 분석 데이터 가져오기
            static_data = self._get_static_analysis(file_hash)
            
            # 동적 분석 데이터 가져오기
            dynamic_data = self._get_dynamic_analysis(file_hash)
            
            # 행위 분석
            behavior_analysis = {
                "network_behavior": self._analyze_network_behavior(static_data, dynamic_data),
                "data_leakage": self._analyze_data_leakage(static_data, dynamic_data),
                "dangerous_apis": self._analyze_dangerous_apis(static_data),
                "runtime_behavior": self._analyze_runtime_behavior(dynamic_data),
                "risk_score": self._calculate_risk_score(static_data, dynamic_data)
            }
            
            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "hash": file_hash,
                "behavior_analysis": behavior_analysis
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _get_static_analysis(self, file_hash: str) -> Dict:
        """정적 분석 데이터 가져오기"""
        response = requests.post(
            f"{self.server}/api/v1/report_json",
            data={"hash": file_hash},
            headers=self.headers
        )
        return response.json()
    
    def _get_dynamic_analysis(self, file_hash: str) -> Dict:
        """동적 분석 데이터 가져오기"""
        response = requests.post(
            f"{self.server}/api/v1/dynamic/report_json",
            data={"hash": file_hash},
            headers=self.headers
        )
        return response.json()
    
    def _analyze_network_behavior(self, static_data: Dict, dynamic_data: Dict) -> Dict:
        """네트워크 행위 분석"""
        network_behavior = {
            "suspicious_urls": [],
            "ssl_pinning": False,
            "insecure_connections": [],
            "data_transmission": {
                "plain_text": [],
                "encrypted": []
            },
            "domains_contacted": []
        }
        
        # 정적 분석에서 URL 추출
        if "urls" in static_data:
            for url in static_data["urls"]:
                if self._is_suspicious_url(url):
                    network_behavior["suspicious_urls"].append(url)
        
        # 동적 분석에서 네트워크 트래픽 분석
        if "traffic" in dynamic_data:
            for traffic in dynamic_data["traffic"]:
                if traffic.get("protocol") == "http":
                    network_behavior["insecure_connections"].append(traffic)
                
                domain = traffic.get("domain")
                if domain:
                    network_behavior["domains_contacted"].append(domain)
        
        return network_behavior
    
    def _analyze_data_leakage(self, static_data: Dict, dynamic_data: Dict) -> Dict:
        """데이터 유출 분석"""
        return {
            "sensitive_data": self._find_sensitive_data(static_data),
            "data_transmission": self._analyze_data_transmission(dynamic_data),
            "storage": self._analyze_data_storage(static_data)
        }
    
    def _analyze_dangerous_apis(self, static_data: Dict) -> Dict:
        """위험한 API 사용 분석"""
        dangerous_apis = {
            "reflection": [],
            "native": [],
            "crypto": [],
            "command": []
        }
        
        # API 호출 분석
        if "api_calls" in static_data:
            for api in static_data["api_calls"]:
                api_type = self._classify_api(api)
                if api_type:
                    dangerous_apis[api_type].append(api)
        
        return dangerous_apis
    
    def _analyze_runtime_behavior(self, dynamic_data: Dict) -> Dict:
        """런타임 행위 분석"""
        return {
            "file_operations": self._analyze_file_operations(dynamic_data),
            "system_calls": self._analyze_system_calls(dynamic_data),
            "permissions_used": self._analyze_permissions_usage(dynamic_data)
        }
    
    def _calculate_risk_score(self, static_data: Dict, dynamic_data: Dict) -> Dict:
        """위험도 점수 계산"""
        risk_factors = {
            "network_security": self._calculate_network_risk(static_data, dynamic_data),
            "data_privacy": self._calculate_privacy_risk(static_data, dynamic_data),
            "code_security": self._calculate_code_risk(static_data),
            "runtime_security": self._calculate_runtime_risk(dynamic_data)
        }
        
        # 전체 위험도 점수 계산 (0-100)
        total_score = sum(risk_factors.values()) / len(risk_factors)
        
        return {
            "total_score": total_score,
            "risk_factors": risk_factors,
            "risk_level": self._get_risk_level(total_score)
        }
    
    def _get_risk_level(self, score: float) -> str:
        """위험도 레벨 결정"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_behavior_report(self, file_hash: str) -> str:
        """행위 분석 보고서 생성"""
        analysis = self.analyze_app_behavior(file_hash)
        
        # 보고서 파일명 생성
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"behavior_analysis_{timestamp}.json"
        
        # 보고서 저장
        with open(report_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        
        return report_file

def main():
    # 설정
    SERVER = "http://127.0.0.1:8000"
    API_KEY = "<YOUR_API_KEY>"
    FILE_HASH = "<TARGET_APP_HASH>"
    
    try:
        # 분석기 초기화
        analyzer = MobSFBehaviorAnalyzer(server=SERVER, api_key=API_KEY)
        
        # 행위 분석 수행
        behavior_analysis = analyzer.analyze_app_behavior(FILE_HASH)
        
        # 보고서 생성
        report_file = analyzer.generate_behavior_report(FILE_HASH)
        
        print(f"Analysis complete. Report saved as: {report_file}")
        
        # 위험도 점수 출력
        risk_score = behavior_analysis["behavior_analysis"]["risk_score"]
        print(f"\nRisk Analysis:")
        print(f"Total Score: {risk_score['total_score']:.2f}")
        print(f"Risk Level: {risk_score['risk_level']}")
        print("\nRisk Factors:")
        for factor, score in risk_score["risk_factors"].items():
            print(f"- {factor}: {score:.2f}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()