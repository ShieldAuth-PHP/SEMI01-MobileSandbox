"""
DEX Analysis Tests Package

이 패키지는 DEX 파일 분석과 관련된 테스트들을 포함
주요 테스트 영역:
- DEX 파일 암호화 탐지
- 파일 구조 분석
- 헤더 검증
"""

# 테스트에서 사용할 상수들
TEST_CONSTANTS = {
    'VALID_DEX_HEADER': b'dex\n035\0',
    'MIN_DEX_SIZE': 40,
    'MAX_DEX_SIZE': 1024 * 1024 * 100  # 100MB
}

# 테스트 유틸리티 함수들
def is_valid_dex_header(header: bytes) -> bool:
    """DEX 파일 헤더 검증"""
    return header.startswith(TEST_CONSTANTS['VALID_DEX_HEADER'])