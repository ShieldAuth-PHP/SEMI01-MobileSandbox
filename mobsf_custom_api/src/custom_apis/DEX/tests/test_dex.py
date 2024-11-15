import os
import sys
import unittest
from unittest.mock import Mock, patch

# 프로젝트 루트 디렉토리를 Python 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))))

from src.custom_apis.DEX.dex_analyzer import MobSFDexAnalyzer
from src.custom_apis.DEX.utils import (calculate_entropy,
                                       check_encryption_pattern)


class TestDEXAnalyzer(unittest.TestCase):
    def setUp(self):
        """테스트 설정"""
        self.analyzer = MobSFDexAnalyzer()
        self.test_hash = "test_hash_123"
        
        # 테스트용 DEX 데이터
        self.test_dex_data = b'dex\n035\0' + b'\x00' * 100
        self.encrypted_dex_data = b'\x12\x34\x56' * 100
        
        # 테스트용 응답 데이터
        self.mock_response = {
            "status": "success",
            "dex_files": [
                {"name": "classes.dex", "size": 1000}
            ]
        }

    @patch('requests.post')
    def test_analyze_dex_success(self, mock_post):
        """DEX 분석 성공 테스트"""
        mock_post.return_value.json.return_value = self.mock_response
        mock_post.return_value.status_code = 200
        
        result = self.analyzer.analyze_dex(self.test_hash)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("dex_files", result)
        
    def test_encryption_detection(self):
        """암호화 탐지 테스트"""
        # 일반 DEX 파일 테스트
        normal_result = check_encryption_pattern(self.test_dex_data)
        self.assertFalse(normal_result['aes_ecb'])
        
        # 암호화된 DEX 파일 테스트
        encrypted_result = check_encryption_pattern(self.encrypted_dex_data)
        self.assertTrue(encrypted_result['aes_ecb'])
        
    def test_entropy_calculation(self):
        """엔트로피 계산 테스트"""
        # 일반 데이터
        normal_entropy = calculate_entropy(self.test_dex_data)
        self.assertLess(normal_entropy, 7.5)
        
        # 암호화된 데이터
        encrypted_entropy = calculate_entropy(self.encrypted_dex_data)
        self.assertGreater(encrypted_entropy, 7.5)

    @patch('requests.post')
    def test_error_handling(self, mock_post):
        """에러 처리 테스트"""
        mock_post.side_effect = Exception("Connection error")
        
        with self.assertRaises(Exception):
            self.analyzer.analyze_dex(self.test_hash)

if __name__ == '__main__':
    unittest.main()