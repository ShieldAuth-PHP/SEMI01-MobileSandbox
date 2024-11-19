import json
import os
from pathlib import Path
from typing import Dict, Optional, Union

import requests
from requests.exceptions import RequestException


class MobSFVisualizationClient:
    """MobSF 시각화 서비스와 상호작용하기 위한 클라이언트 클래스"""

    def __init__(self, base_url: str, api_key: str):
        """
        MobSFVisualizationClient 초기화
        
        Args:
            base_url (str): 시각화 서비스의 기본 URL
            api_key (str): API 인증 키
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Authorization': api_key,
            'Content-Type': 'application/json'
        }

    def check_health(self) -> Dict:
        """
        서버 상태 확인
        
        Returns:
            Dict: 서버 상태 정보를 담은 딕셔너리
        
        Raises:
            RequestException: API 요청 실패 시
        """
        try:
            response = requests.get(f"{self.base_url}/health")
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            raise Exception(f"Failed to check server health: {str(e)}")

    def get_visualization(
        self,
        analysis_id: str,
        report_type: str,
        visualization_type: str
    ) -> Dict:
        """
        시각화 데이터 요청
        
        Args:
            analysis_id (str): MobSF 분석 ID
            report_type (str): 리포트 타입 ('static', 'dynamic', 'combined')
            visualization_type (str): 시각화 타입 ('permissions', 'security_score')
            
        Returns:
            Dict: 시각화 데이터를 담은 딕셔너리
            
        Raises:
            RequestException: API 요청 실패 시
            ValueError: 잘못된 시각화 타입 지정 시
        """
        if visualization_type not in ['permissions', 'security_score']:
            raise ValueError(f"Unsupported visualization type: {visualization_type}")

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
        except RequestException as e:
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