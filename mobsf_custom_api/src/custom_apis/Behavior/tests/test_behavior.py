import unittest
from datetime import datetime
from unittest.mock import Mock, patch

from ...Behavior.behavior_analyzer import MobSFBehaviorAnalyzer
from ...Behavior.utils import analyze_network_behavior, calculate_risk_score


class TestBehaviorAnalyzer(unittest.TestCase):
    def setUp(self):
        """테스트 설정"""
        self.analyzer = MobSFBehaviorAnalyzer()
        self.test_hash = "test_hash_123"
        
        # 테스트용 행위 데이터
        self.test_behavior_data = {
            "urls": [
                "http://suspicious.com",
                "https://safe.com"
            ],
            "api_calls": [
                {"api": "android.permission.READ_CONTACTS", "risk": "high"},
                {"api": "android.permission.INTERNET", "risk": "low"}
            ]
        }

    @patch('requests.post')
    def test_analyze_behavior_success(self, mock_post):
        """행위 분석 성공 테스트"""
        mock_post.return_value.json.return_value = {
            "status": "success",
            "behavior_data": self.test_behavior_data
        }
        
        result = self.analyzer.analyze_app_behavior(self.test_hash)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("behavior_data", result)
        
    def test_network_analysis(self):
        """네트워크 행위 분석 테스트"""
        network_result = analyze_network_behavior(self.test_behavior_data)
        
        self.assertEqual(len(network_result["suspicious_urls"]), 1)
        self.assertEqual(network_result["secure_connections"], 1)
        self.assertEqual(network_result["insecure_connections"], 1)
        
    def test_risk_score_calculation(self):
        """위험도 점수 계산 테스트"""
        risk_result = calculate_risk_score(self.test_behavior_data)
        
        self.assertIn("total_score", risk_result)
        self.assertIn("risk_level", risk_result)
        self.assertTrue(0 <= risk_result["total_score"] <= 100)

    def test_behavior_validation(self):
        """행위 데이터 검증 테스트"""
        invalid_data = {"invalid": "data"}
        
        with self.assertRaises(ValueError):
            self.analyzer.validate_behavior_data(invalid_data)

if __name__ == '__main__':
    unittest.main()