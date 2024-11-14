import json
import os
from typing import Dict

from .behavior_analyzer import MobSFBehaviorAnalyzer


def load_schema() -> Dict:
    """행위 분석 관련 JSON 스키마 로드"""
    schema_path = os.path.join(os.path.dirname(__file__), 'behavior_analysis.json')
    with open(schema_path, 'r') as f:
        return json.load(f)

# 버전 정보
__version__ = '1.0.0'

# 메타데이터
__author__ = 'your name'
__description__ = 'MobSF 행위 분석 모듈'

# 분석 유형 정의
ANALYSIS_TYPES = {
    'NETWORK': 'network_behavior',
    'API': 'api_usage',
    'DATA': 'data_leakage',
    'RUNTIME': 'runtime_behavior',
    'PERMISSION': 'permission_analysis'
}

# 위험도 레벨 정의
RISK_LEVELS = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
}

class BehaviorAnalysisConfig:
    """행위 분석 설정"""
    DEFAULT_ANALYSIS_TYPES = ['NETWORK', 'API', 'DATA']
    TIMEOUT = 300  # 초
    MAX_DEPTH = 3  # 분석 깊이
    
    @classmethod
    def get_default_config(cls) -> Dict:
        return {
            'analysis_types': cls.DEFAULT_ANALYSIS_TYPES,
            'timeout': cls.TIMEOUT,
            'max_depth': cls.MAX_DEPTH
        }

# 주요 클래스와 함수들을 패키지 레벨로 노출
__all__ = [
    'MobSFBehaviorAnalyzer',
    'load_schema',
    'BehaviorAnalysisConfig',
    'ANALYSIS_TYPES',
    'RISK_LEVELS'
]

# 스키마 데이터를 모듈 레벨에서 사용 가능하게 함
schema = load_schema()

# 초기화 로그
if __name__ != "__main__":
    print(f"Initializing MobSF Behavior Analysis Module v{__version__}")
    print(f"Available Analysis Types: {', '.join(ANALYSIS_TYPES.keys())}")

def get_risk_level(score: float) -> str:
    """점수에 따른 위험도 레벨 반환"""
    if score >= 90:
        return 'CRITICAL'
    elif score >= 70:
        return 'HIGH'
    elif score >= 50:
        return 'MEDIUM'
    elif score >= 30:
        return 'LOW'
    else:
        return 'INFO'

def validate_analysis_type(analysis_type: str) -> bool:
    """분석 유형 유효성 검사"""
    return analysis_type.upper() in ANALYSIS_TYPES

# 유틸리티 함수들도 함께 제공
def format_analysis_result(result: Dict) -> Dict:
    """분석 결과 포맷팅"""
    return {
        'status': result.get('status', 'unknown'),
        'risk_level': get_risk_level(result.get('score', 0)),
        'details': result.get('details', {}),
        'timestamp': result.get('timestamp', '')
    }