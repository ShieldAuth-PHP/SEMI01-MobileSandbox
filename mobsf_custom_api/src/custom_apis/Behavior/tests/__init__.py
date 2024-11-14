"""
Behavior Analysis Tests Package

이 패키지는 앱 행위 분석과 관련된 테스트들을 포함
주요 테스트 영역:
- 네트워크 행위 분석
- API 호출 패턴
- 데이터 유출 탐지
"""

# 테스트에서 사용할 상수들
TEST_CONSTANTS = {
    'RISK_LEVELS': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    'ANALYSIS_TYPES': ['network', 'api', 'data', 'runtime'],
    'MAX_API_CALLS': 1000
}

# 테스트 유틸리티 함수들
def get_risk_level(score: float) -> str:
    """위험도 점수를 레벨로 변환"""
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    return 'LOW'