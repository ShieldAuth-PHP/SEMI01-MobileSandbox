import json
import unittest
from unittest.mock import patch

from ..custom_apis.Behavior.behavior_analyzer import MobSFBehaviorAnalyzer
from ..custom_apis.DEX.dex_analyzer import MobSFDexAnalyzer


class TestIntegration(unittest.TestCase):
    def setUp(self):
        """통합 테스트 설정"""
        self.dex_analyzer = MobSFDexAnalyzer()
        self.behavior_analyzer = MobSFBehaviorAnalyzer()
        self.test_hash = "test_hash_123"
        
        # 테스트용 JSON 파일 로드
        with open('test_data/sample_apk.json', 'r') as f:
            self.test_data = json.load(f)

    @patch('requests.post')
    def test_full_analysis_flow(self, mock_post):
        """전체 분석 흐름 테스트"""
        # DEX 분석
        mock_post.return_value.json.return_value = self.test_data["dex_analysis"]
        dex_result = self.dex_analyzer.analyze_dex(self.test_hash)
        
        # 행위 분석
        mock_post.return_value.json.return_value = self.test_data["behavior_analysis"]
        behavior_result = self.behavior_analyzer.analyze_app_behavior(self.test_hash)
        
        # 결과 검증
        self.assertEqual(dex_result["status"], "success")
        self.assertEqual(behavior_result["status"], "success")
        
        # 결과 연관성 검증
        if dex_result.get("encrypted_dex"):
            self.assertIn("encryption_analysis", behavior_result)

    def test_error_propagation(self):
        """에러 전파 테스트"""
        with patch('requests.post') as mock_post:
            mock_post.side_effect = Exception("API Error")
            
            with self.assertRaises(Exception):
                self.dex_analyzer.analyze_dex(self.test_hash)
            
            with self.assertRaises(Exception):
                self.behavior_analyzer.analyze_app_behavior(self.test_hash)

if __name__ == '__main__':
    unittest.main()