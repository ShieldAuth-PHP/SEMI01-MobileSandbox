import json
import os

from .dex_analyzer import MobSFDexAnalyzer


# 현재 디렉토리에서 JSON 스키마 로드
def load_schema():
    schema_path = os.path.join(os.path.dirname(__file__), 'dex_analysis_encrypted.json')
    with open(schema_path, 'r') as f:
        return json.load(f)

# 주요 클래스와 함수들을 패키지 레벨로 노출
__all__ = [
    'MobSFDexAnalyzer',
    'load_schema'
]

# 버전 정보
__version__ = '1.0.0'

# 스키마 데이터를 모듈 레벨에서 사용 가능하게 함
schema = load_schema()