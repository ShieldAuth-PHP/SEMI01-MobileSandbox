from datetime import datetime
from typing import Dict, List, Optional


def analyze_network_behavior(data: Dict) -> Dict:
    """네트워크 행위 분석"""
    network_data = data.get('network_analysis', {})
    result = {
        'suspicious_urls': [],
        'secure_connections': 0,
        'insecure_connections': 0,
        'data_leakage_risks': []
    }
    
    # URL 분석
    for url in network_data.get('urls', []):
        if _is_suspicious_url(url):
            result['suspicious_urls'].append(url)
        if url.startswith('https'):
            result['secure_connections'] += 1
        else:
            result['insecure_connections'] += 1
    
    return result

def calculate_risk_score(data: Dict) -> Dict:
    """위험도 점수 계산"""
    scores = {
        'network_score': _calculate_network_score(data),
        'api_score': _calculate_api_score(data),
        'permission_score': _calculate_permission_score(data)
    }
    
    total_score = sum(scores.values()) / len(scores)
    
    return {
        'total_score': total_score,
        'category_scores': scores,
        'risk_level': _get_risk_level(total_score)
    }

def _is_suspicious_url(url: str) -> bool:
    """의심스러운 URL 판단"""
    suspicious_patterns = [
        'malware', 'hack', 'exploit',
        '.ru/', '.cn/', 'http://'
    ]
    return any(pattern in url.lower() for pattern in suspicious_patterns)

def _calculate_network_score(data: Dict) -> float:
    """네트워크 위험도 점수 계산"""
    network_data = analyze_network_behavior(data)
    score = 100.0
    
    # 감점 요소
    score -= len(network_data['suspicious_urls']) * 10
    score -= network_data['insecure_connections'] * 5
    
    return max(0.0, min(score, 100.0))

def _calculate_api_score(data: Dict) -> float:
    """API 사용 위험도 점수 계산"""
    api_calls = data.get('api_analysis', {}).get('api_calls', [])
    score = 100.0
    
    for api in api_calls:
        if api.get('risk') == 'high':
            score -= 10
        elif api.get('risk') == 'medium':
            score -= 5
    
    return max(0.0, min(score, 100.0))

def _calculate_permission_score(data: Dict) -> float:
    """권한 사용 위험도 점수 계산"""
    permissions = data.get('permission_analysis', {})
    score = 100.0
    
    dangerous_count = len(permissions.get('dangerous_permissions', []))
    score -= dangerous_count * 15
    
    return max(0.0, min(score, 100.0))

def _get_risk_level(score: float) -> str:
    """위험도 레벨 결정"""
    if score >= 80:
        return 'LOW'
    elif score >= 60:
        return 'MEDIUM'
    elif score >= 40:
        return 'HIGH'
    return 'CRITICAL'