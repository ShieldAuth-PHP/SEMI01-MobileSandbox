import json
import os
import unittest
from datetime import datetime
from pathlib import Path
from typing import Dict

import requests

from mobsf_visualization_client import MobSFVisualizationClient


class TestMobSFVisualizationClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """테스트 클래스 초기화"""
        # 테스트 환경 설정
        cls.api_key = os.getenv("MOBSF_API_KEY", "test_api_key")
        cls.base_url = os.getenv("MOBSF_VIZ_URL", "http://localhost:8001")
        cls.test_dir = Path("test_outputs")
        cls.test_dir.mkdir(exist_ok=True)
        
        # 테스트용 클라이언트 초기화
        cls.client = MobSFVisualizationClient(
            base_url=cls.base_url,
            api_key=cls.api_key
        )
        
        # 테스트용 분석 ID (실제 MobSF에서 분석한 APK의 ID 사용)
        cls.test_analysis_id = "test_analysis_id"  # 실제 분석 ID로 변경 필요

    def setUp(self):
        """각 테스트 케이스 전 실행"""
        # 서버 상태 확인
        health = self.client.check_health()
        if health.get("status") != "healthy":
            self.skipTest("MobSF Visualization server is not healthy")

    def test_server_health(self):
        """서버 상태 확인 테스트"""
        response = self.client.check_health()
        self.assertEqual(response.get("status"), "healthy")
        self.assertIn("mobsf_client", response)

    def test_permissions_visualization(self):
        """권한 분석 시각화 테스트"""
        try:
            # 시각화 요청 - static 분석용
            response = self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="static",  # 명확하게 static으로 지정
                visualization_type="permissions"
            )
            
            print(f"Visualization response: {response}")  # 디버깅용
            
            self.assertIn("chart_data", response)
            self.assertIsInstance(response["chart_data"], dict)
            
        except Exception as e:
            self.fail(f"Test failed with error: {str(e)}")

    def test_dynamic_analysis_visualization(self):
        """동적 분석 시각화 테스트"""
        try:
            # 시각화 요청 - dynamic 분석용
            response = self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="dynamic",  # 동적 분석용
                visualization_type="security_score"  # 동적 분석에 적합한 시각화 타입 선택
            )
            
            print(f"Dynamic visualization response: {response}")  # 디버깅용
            
            self.assertIn("chart_data", response)
            self.assertIsInstance(response["chart_data"], dict)
            
        except Exception as e:
            self.fail(f"Dynamic test failed with error: {str(e)}")

    def test_security_score_visualization(self):
        """보안 점수 시각화 테스트"""
        try:
            response = self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="static",
                visualization_type="security_score"
            )
            
            # 응답 검증
            self.assertIn("chart_data", response)
            self.assertIsInstance(response["chart_data"], dict)
            
            # 결과 저장
            output_path = self.test_dir / "security_score_viz.json"
            success = self.client.save_visualization(
                response,
                str(output_path)
            )
            self.assertTrue(success)
            self.assertTrue(output_path.exists())
            
        except requests.exceptions.RequestException as e:
            self.fail(f"Failed to get security score visualization: {str(e)}")

    def test_pdf_report_generation(self):
        """PDF 보고서 생성 테스트"""
        try:
            output_path = self.test_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = self.client.get_pdf_report(
                analysis_id=self.test_analysis_id,
                report_type="static",
                save_path=str(output_path)
            )
            
            # PDF 생성 검증
            self.assertIsNotNone(pdf_path)
            self.assertTrue(Path(pdf_path).exists())
            self.assertTrue(Path(pdf_path).stat().st_size > 0)
            
        except requests.exceptions.RequestException as e:
            self.fail(f"Failed to generate PDF report: {str(e)}")

    def test_invalid_visualization_type(self):
        """잘못된 시각화 타입 테스트"""
        with self.assertRaises(Exception):
            self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="static",
                visualization_type="invalid_type"
            )

    def test_save_visualization_formats(self):
        """시각화 저장 포맷 테스트"""
        test_data = {"test": "data"}
        
        # JSON 포맷 테스트
        json_path = self.test_dir / "test_viz.json"
        success = self.client.save_visualization(
            test_data,
            str(json_path),
            format="json"
        )
        self.assertTrue(success)
        self.assertTrue(json_path.exists())
        
        # 잘못된 포맷 테스트
        with self.assertRaises(ValueError):
            self.client.save_visualization(
                test_data,
                "test.invalid",
                format="invalid_format"
            )

    @classmethod
    def tearDownClass(cls):
        """테스트 클래스 종료 시 정리"""
        # 테스트 출력 파일 정리
        if cls.test_dir.exists():
            for file in cls.test_dir.glob("*"):
                try:
                    file.unlink()
                except Exception:
                    pass
            cls.test_dir.rmdir()

def main():
    # 커맨드라인에서 실행 시 추가 옵션 처리
    import argparse
    parser = argparse.ArgumentParser(description='Test MobSF Visualization Client')
    parser.add_argument('--api-key', help='MobSF API Key')
    parser.add_argument('--server-url', help='MobSF Visualization Server URL')
    parser.add_argument('--analysis-id', help='Test Analysis ID')
    args = parser.parse_args()
    
    # 환경 변수 설정
    if args.api_key:
        os.environ['MOBSF_API_KEY'] = args.api_key
    if args.server_url:
        os.environ['MOBSF_VIZ_URL'] = args.server_url
    if args.analysis_id:
        TestMobSFVisualizationClient.test_analysis_id = args.analysis_id
    
    # 테스트 실행
    unittest.main(argv=[''])

if __name__ == "__main__":
    main()