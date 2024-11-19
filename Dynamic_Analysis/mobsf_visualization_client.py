import json
import os
from pathlib import Path
from typing import Dict, Optional, Union

import requests
from requests.exceptions import RequestException


class MobSFVisualizationClient:
    def __init__(self, viz_url: str, api_key: str, mobsf_url: str = "http://localhost:8000"):
        """
        초기화
        Args:
            base_url: 시각화 서버 URL (8001 포트)
            api_key: MobSF API 키
            mobsf_url: MobSF 서버 URL (8000 포트)
        """
        self.base_url = viz_url.rstrip('/')
        self.mobsf_url = mobsf_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            "Authorization": api_key,
            "Content-Type": "application/json"
        }

    def check_health(self) -> Dict:
        """시각화 서버 상태 확인 (8001 포트)"""
        try:
            response = requests.get(f"{self.base_url}/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to check visualization server health: {str(e)}")

    def get_report(self, analysis_id: str, report_type: str = "static") -> Dict:
        try:
            # 정적 분석 리포트
            if report_type == "static":
                endpoint = "/api/v1/report_json"
                data = {
                    "hash": analysis_id,
                    "scan_type": "apk",
                    "type": "apk",
                    "api": "true"
                }
            # 동적 분석 리포트
            else:
                endpoint = "/api/v1/dynamic/report_json"
                data = {
                    "hash": analysis_id,
                    "type": "apk",
                    "report_type": "json",
                    "api": "true"
                }

            url = f"{self.mobsf_url}{endpoint}"
            print(f"Requesting MobSF report from: {url}")
            print(f"Request data: {data}")  # 디버깅용
            
            # API 키를 헤더에 추가
            headers = {
                "Authorization": self.api_key,
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                url,
                headers=headers,
                json=data
            )
            
            print(f"Response status: {response.status_code}")
            print(f"Response content: {response.text}")
            
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error details: {str(e)}")
            raise Exception(f"Failed to get MobSF report: {str(e)}")

    def get_visualization(self, analysis_id: str, report_type: str, visualization_type: str, report_data: Dict = None) -> Dict:
        """시각화 서버에 시각화 요청 (8001 포트)"""
        try:
            if report_data is None:
                report_data = self.get_report(analysis_id, report_type)
            
            # 시각화 서버에 시각화 요청
            response = requests.post(
                f"{self.base_url}/api/v1/visualize",
                headers=self.headers,
                json={
                    "analysis_id": analysis_id,
                    "report_type": report_type,
                    "visualization_type": visualization_type,
                    "report_data": report_data  # 리포트 데이터 포함
                }
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get visualization: {str(e)}")

    def get_pdf_report(
        self,
        analysis_id: str,
        report_type: str,
        save_path: str
    ) -> Optional[str]:
        """
        PDF 보고서 생성 및 저장
        
        Args:
            analysis_id (str): MobSF 분석 ID
            report_type (str): 리포트 타입 ('static', 'dynamic', 'combined')
            save_path (str): PDF 파일 저장 경로
            
        Returns:
            Optional[str]: 저장된 PDF 파일 경로 또는 None
            
        Raises:
            RequestException: API 요청 실패 시
            IOError: 파일 저장 실패 시
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/visualization_pdf",
                headers=self.headers,
                json={
                    "analysis_id": analysis_id,
                    "report_type": report_type,
                    "visualization_type": "all"
                },
                stream=True
            )
            response.raise_for_status()

            # PDF 파일 저장
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            return save_path
        except RequestException as e:
            raise Exception(f"Failed to get PDF report: {str(e)}")
        except IOError as e:
            raise Exception(f"Failed to save PDF file: {str(e)}")

    def save_visualization(
        self,
        data: Dict,
        file_path: str,
        format: str = 'json'
    ) -> bool:
        """
        시각화 데이터를 파일로 저장
        
        Args:
            data (Dict): 저장할 시각화 데이터
            file_path (str): 저장할 파일 경로
            format (str): 저장 형식 ('json')
            
        Returns:
            bool: 저장 성공 여부
            
        Raises:
            ValueError: 지원하지 않는 저장 형식 지정 시
            IOError: 파일 저장 실패 시
        """
        if format.lower() != 'json':
            raise ValueError(f"Unsupported save format: {format}")

        try:
            save_dir = os.path.dirname(file_path)
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            return True
        except Exception as e:
            raise Exception(f"Failed to save visualization: {str(e)}")
        
    def check_visualization_health(self) -> Dict:
        return self.check_health()

    def check_mobsf_health(self) -> bool:
        try:
            response = requests.get(f"{self.mobsf_url}/api/v1/health")
            return response.status_code == 200
        except:
            return False

    def get_mobsf_report(self, analysis_id: str, report_type: str) -> Dict:
        return self.get_report(analysis_id, report_type)