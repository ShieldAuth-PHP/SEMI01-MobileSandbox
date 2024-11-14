import json
import os

import pytest


@pytest.fixture
def sample_behavior_data():
    """테스트용 행위 분석 데이터"""
    return {
        "urls": [
            "http://suspicious.com",
            "https://safe.com"
        ],
        "api_calls": [
            {
                "api": "android.permission.READ_CONTACTS",
                "risk": "high",
                "count": 5
            },
            {
                "api": "android.permission.INTERNET",
                "risk": "low",
                "count": 10
            }
        ],
        "network_behavior": {
            "suspicious_connections": 2,
            "data_leakage": True
        }
    }

@pytest.fixture
def mock_behavior_response():
    """목업 행위 분석 응답"""
    return {
        "status": "success",
        "timestamp": "2024-01-01T00:00:00",
        "behavior_data": {
            "risk_score": 75,
            "risk_level": "HIGH",
            "details": {}
        }
    }

@pytest.fixture
def behavior_analysis_schema():
    """행위 분석 스키마"""
    schema_path = os.path.join(
        os.path.dirname(__file__),
        '..',
        'behavior_analysis.json'
    )
    with open(schema_path, 'r') as f:
        return json.load(f)