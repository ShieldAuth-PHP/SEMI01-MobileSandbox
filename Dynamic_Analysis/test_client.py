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
        # API 키 및 서버 URL 설정
        cls.api_key = os.getenv("MOBSF_API_KEY", "test_api_key")
        cls.viz_url = os.getenv("MOBSF_VIZ_URL", "http://localhost:8001")  # 시각화 서버
        cls.mobsf_url = os.getenv("MOBSF_URL", "http://localhost:8000")    # MobSF 서버
        
        print(f"Visualization Server URL: {cls.viz_url}")
        print(f"MobSF Server URL: {cls.mobsf_url}")
        print(f"API Key Length: {len(cls.api_key)}")
        
        # 테스트 디렉토리 설정
        cls.test_dir = Path("test_outputs")
        cls.test_dir.mkdir(exist_ok=True)
        
        # 클라이언트 초기화
        cls.client = MobSFVisualizationClient(
            viz_url=cls.viz_url,
            mobsf_url=cls.mobsf_url,
            api_key=cls.api_key
        )
        
        # APK 분석 ID 설정
        cls.test_analysis_id = os.getenv("MOBSF_ANALYSIS_ID", "test_analysis_id")
        print(f"Using Analysis ID: {cls.test_analysis_id}")
    
    def test_permissions_visualization(self):
        """권한 분석 시각화 테스트"""
        try:
            # 먼저 MobSF에서 리포트 가져오기
            print(f"Getting report for analysis ID: {self.test_analysis_id}")
            report = self.client.get_mobsf_report(
                analysis_id=self.test_analysis_id,
                report_type="static"
            )
            self.assertIsInstance(report, dict)
            print("Successfully retrieved MobSF report")

            # 권한 시각화 요청
            print("Requesting permissions visualization")
            response = self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="static",
                visualization_type="permissions",
                report_data=report
            )
            
            print(f"Visualization response: {response}")  # 디버깅용
            
            # 응답 검증
            self.assertIn("chart_data", response)
            self.assertIsInstance(response["chart_data"], dict)
            
            # 결과 저장
            output_path = self.test_dir / "permissions_viz.json"
            success = self.client.save_visualization(
                response,
                str(output_path)
            )
            self.assertTrue(success)
            self.assertTrue(output_path.exists())
            print(f"Visualization saved to: {output_path}")
            
        except Exception as e:
            self.fail(f"Permissions visualization test failed: {str(e)}")

    def setUp(self):
        """각 테스트 케이스 전 실행"""
        # 시각화 서버 상태 확인
        try:
            health = self.client.check_health()
            if health.get("status") != "healthy":
                self.skipTest("Visualization server is not healthy")
        except Exception as e:
            print(f"Error during health check: {str(e)}") # 디버깅용 출력
            self.skipTest(f"Server health check failed: {str(e)}")

    def test_server_health(self):
        """서버 상태 확인 테스트"""
        # 시각화 서버 상태
        viz_health = self.client.check_visualization_health()
        self.assertEqual(viz_health.get("status"), "healthy")
        
        # MobSF 서버 상태
        mobsf_health = self.client.check_mobsf_health()
        self.assertTrue(mobsf_health)

    def test_static_analysis(self):
        """정적 분석 테스트"""
        try:
            # 정적 분석 리포트 가져오기
            report = self.client.get_mobsf_report(
                analysis_id=self.test_analysis_id,
                report_type="static"
            )
            self.assertIsInstance(report, dict)
            print("Static analysis report retrieved successfully")
            
            # 권한 시각화
            viz_response = self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="static",
                visualization_type="permissions",
                report_data=report
            )
            self.assertIn("chart_data", viz_response)
            print("Permissions visualization created successfully")
            
        except Exception as e:
            self.fail(f"Static analysis test failed: {str(e)}")

    def test_dynamic_analysis(self):
        """동적 분석 테스트"""
        try:
            # 동적 분석 리포트 가져오기
            report = self.client.get_mobsf_report(
                analysis_id=self.test_analysis_id,
                report_type="dynamic"
            )
            self.assertIsInstance(report, dict)
            print("Dynamic analysis report retrieved successfully")
            
            # 보안 점수 시각화
            viz_response = self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="dynamic",
                visualization_type="security_score",
                report_data=report
            )
            self.assertIn("chart_data", viz_response)
            print("Security score visualization created successfully")
            
        except Exception as e:
            self.fail(f"Dynamic analysis test failed: {str(e)}")

    def test_pdf_report_generation(self):
        """PDF 보고서 생성 테스트"""
        try:
            output_path = self.test_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = self.client.get_pdf_report(
                analysis_id=self.test_analysis_id,
                report_type="static",
                save_path=str(output_path)
            )
            
            self.assertIsNotNone(pdf_path)
            self.assertTrue(Path(pdf_path).exists())
            self.assertTrue(Path(pdf_path).stat().st_size > 0)
            print(f"PDF report generated successfully: {pdf_path}")
            
        except Exception as e:
            self.fail(f"PDF report generation failed: {str(e)}")

    def test_error_handling(self):
        """에러 처리 테스트"""
        # 잘못된 시각화 타입
        with self.assertRaises(ValueError):
            self.client.get_visualization(
                analysis_id=self.test_analysis_id,
                report_type="static",
                visualization_type="invalid_type"
            )
        
        # 잘못된 분석 ID
        with self.assertRaises(Exception):
            self.client.get_mobsf_report(
                analysis_id="invalid_id",
                report_type="static"
            )

    @classmethod
    def tearDownClass(cls):
        """테스트 정리"""
        if cls.test_dir.exists():
            for file in cls.test_dir.glob("*"):
                try:
                    file.unlink()
                except Exception:
                    pass
            cls.test_dir.rmdir()


def main():
    # 커맨드라인 인자 파싱
    import argparse
    parser = argparse.ArgumentParser(description='Test MobSF Visualization Client')
    parser.add_argument('--api-key', help='MobSF API Key')
    parser.add_argument('--viz-url', help='Visualization Server URL')
    parser.add_argument('--mobsf-url', help='MobSF Server URL')
    parser.add_argument('--analysis-id', help='APK Analysis ID')
    args = parser.parse_args()
    
    # 환경 변수 설정
    if args.api_key:
        os.environ['MOBSF_API_KEY'] = args.api_key
    if args.viz_url:
        os.environ['MOBSF_VIZ_URL'] = args.viz_url
    if args.mobsf_url:
        os.environ['MOBSF_URL'] = args.mobsf_url
    if args.analysis_id:
        os.environ['MOBSF_ANALYSIS_ID'] = args.analysis_id
    
    # 테스트 실행
    unittest.main(argv=[''])

if __name__ == "__main__":
    main()