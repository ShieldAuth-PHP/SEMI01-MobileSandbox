"""
Integration Tests Package

이 패키지는 MobSF 커스텀 API의 통합 테스트들을 포함
주요 테스트 영역:
- 전체 분석 파이프라인
- 컴포넌트 간 상호작용
- 엔드-투-엔드 시나리오
"""

import os
from typing import Dict

# 테스트 환경 설정
TEST_ENV = {
    'MOBSF_API_KEY': 'test_key_123',
    'MOBSF_SERVER': 'http://localhost:8000',
    'TEST_DATA_DIR': os.path.join(os.path.dirname(__file__), 'test_data')
}

# 테스트 유틸리티 함수들
def load_test_data(filename: str) -> Dict:
    """테스트 데이터 파일 로드"""
    file_path = os.path.join(TEST_ENV['TEST_DATA_DIR'], filename)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            import json
            return json.load(f)
    return {}

def get_test_file_path(filename: str) -> str:
    """테스트 파일의 전체 경로 반환"""
    return os.path.join(TEST_ENV['TEST_DATA_DIR'], filename)

# 테스트 상수
MAX_EXECUTION_TIME = 300  # 초
DEFAULT_TIMEOUT = 60     # 초