import binascii
import math
from typing import Dict, List, Optional


def calculate_entropy(data: bytes) -> float:
    """데이터의 엔트로피 계산"""
    if not data:
        return 0.0
    
    # 바이트 빈도수 계산
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Shannon 엔트로피 계산
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
        
    return entropy

def check_encryption_pattern(data: bytes) -> Dict[str, bool]:
    """암호화 패턴 검사"""
    patterns = {
        'aes_ecb': False,
        'custom_encryption': False
    }
    
    # AES-ECB 패턴 확인
    if len(data) % 16 == 0 and calculate_entropy(data) > 7.5:
        patterns['aes_ecb'] = True
    
    # 기타 암호화 패턴 확인
    if not data.startswith(b'dex\n') and calculate_entropy(data) > 6.5:
        patterns['custom_encryption'] = True
    
    return patterns

def validate_dex_header(data: bytes) -> bool:
    """DEX 파일 헤더 유효성 검사"""
    return data.startswith(b'dex\n')

def format_dex_info(dex_data: Dict) -> Dict:
    """DEX 파일 정보 포맷팅"""
    return {
        'name': dex_data.get('name', ''),
        'size': dex_data.get('size', 0),
        'encryption_status': {
            'is_encrypted': dex_data.get('is_encrypted', False),
            'encryption_type': dex_data.get('encryption_type', None),
            'confidence': dex_data.get('confidence', 0)
        },
        'analysis_details': dex_data.get('analysis_details', {})
    }

def analyze_dex_content(data: bytes) -> Dict:
    """DEX 파일 내용 분석"""
    encryption_check = check_encryption_pattern(data)
    entropy = calculate_entropy(data)
    
    return {
        'is_encrypted': any(encryption_check.values()),
        'encryption_type': 'AES-ECB' if encryption_check['aes_ecb'] else 'UNKNOWN',
        'entropy': entropy,
        'encryption_confidence': entropy / 8.0 * 100  # 0-100% 스케일
    }