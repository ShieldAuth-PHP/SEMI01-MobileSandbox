import json
import os
from datetime import datetime
from typing import BinaryIO, Dict, Optional, Union

import requests


class MobSFVisualizationClient:
    def __init__(self, base_url: str = "http://localhost:8001", api_key: Optional[str] = None):
        """
        MobSF 시각화 API 클라이언트 초기화
        
        Args:
            base_url: API 서버 기본 URL (기본값: "http://localhost:8001")
            api_key: MobSF API 키 (선택사항)
        """
        self.base_url = base_url.rstrip('/')
        self.headers = {
            "Content-Type": "application/json"
        }
        if api_key:
            self.headers["Authorization"] = api_key

    def check_health(self) -> Dict:
        """
        서버 상태 확인
        
        Returns:
            Dict: 서버 상태 정보
        """
        try:
            response = requests.get(
                f"{self.base_url}/health",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Health check failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def get_visualization(
        self, 
        analysis_id: str, 
        report_type: str, 
        visualization_type: str
    ) -> Dict:
        """
        시각화 데이터 요청
        
        Args:
            analysis_id: 분석 ID
            report_type: 리포트 타입 ('static', 'dynamic', 'combined')
            visualization_type: 시각화 타입 ('permissions', 'security_score')
            
        Returns:
            Dict: 시각화 데이터
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/visualize",
                headers=self.headers,
                json={
                    "analysis_id": analysis_id,
                    "report_type": report_type,
                    "visualization_type": visualization_type
                }
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Visualization request failed: {str(e)}")
            return {"error": str(e)}
    
    def get_pdf_report(
        self, 
        analysis_id: str, 
        report_type: str,
        save_path: Optional[str] = None
    ) -> Union[bytes, str]:
        """
        PDF 보고서 요청 및 저장
        
        Args:
            analysis_id: 분석 ID
            report_type: 리포트 타입 ('static', 'dynamic', 'combined')
            save_path: PDF 저장 경로 (선택사항)
            
        Returns:
            Union[bytes, str]: PDF 데이터 또는 저장된 파일 경로
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/visualization_pdf",
                headers=self.headers,
                json={
                    "analysis_id": analysis_id,
                    "report_type": report_type
                }
            )
            response.raise_for_status()
            
            # PDF 저장
            if save_path:
                pdf_path = save_path
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pdf_path = f"security_analysis_{analysis_id}_{timestamp}.pdf"
            
            with open(pdf_path, "wb") as f:
                f.write(response.content)
            
            return pdf_path
            
        except requests.exceptions.RequestException as e:
            print(f"PDF report request failed: {str(e)}")
            return None

    def save_visualization(
        self,
        visualization_data: Dict,
        output_path: str,
        format: str = "json"
    ) -> bool:
        """
        시각화 데이터 저장
        
        Args:
            visualization_data: 시각화 데이터
            output_path: 저장 경로
            format: 저장 형식 ('json' 또는 'html')
            
        Returns:
            bool: 저장 성공 여부
        """
        try:
            if format == "json":
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(visualization_data, f, indent=2, ensure_ascii=False)
            elif format == "html":
                # HTML 형식으로 저장하는 로직 구현 필요
                pass
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            return True
        except Exception as e:
            print(f"Failed to save visualization: {str(e)}")
            return False

def main():
    # API 키 설정 (환경 변수 또는 직접 입력)
    api_key = os.getenv("MOBSF_API_KEY", "YOUR_API_KEY")
    
    # 클라이언트 생성
    client = MobSFVisualizationClient(api_key=api_key)
    
    try:
        # 1. 서버 상태 확인
        print("\n1. Checking server health...")
        health = client.check_health()
        print("Server Health:", json.dumps(health, indent=2))
        
        # 2. 권한 분석 시각화 테스트
        print("\n2. Testing permissions visualization...")
        viz_response = client.get_visualization(
            analysis_id="test_id",
            report_type="static",
            visualization_type="permissions"
        )
        print("Permissions Visualization Response:", json.dumps(viz_response, indent=2))
        
        # 시각화 데이터 저장
        client.save_visualization(
            viz_response,
            "permissions_visualization.json"
        )
        
        # 3. 보안 점수 시각화 테스트
        print("\n3. Testing security score visualization...")
        security_viz = client.get_visualization(
            analysis_id="test_id",
            report_type="static",
            visualization_type="security_score"
        )
        print("Security Score Visualization Response:", json.dumps(security_viz, indent=2))
        
        # 4. PDF 보고서 생성 테스트
        print("\n4. Testing PDF report generation...")
        pdf_path = client.get_pdf_report(
            analysis_id="test_id",
            report_type="static",
            save_path="security_report.pdf"
        )
        
        if pdf_path:
            print(f"PDF report saved as: {pdf_path}")
        else:
            print("Failed to generate PDF report")
        
    except requests.exceptions.ConnectionError:
        print("Error: Cannot connect to the server. Make sure it's running.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()