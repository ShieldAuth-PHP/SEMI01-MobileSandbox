import json
import os
from unittest.mock import Mock

import pytest


@pytest.fixture(scope="session")
def test_data():
    """전체 테스트 데이터 로드"""
    data_path = os.path.join(
        os.path.dirname(__file__),
        'test_data',
        'sample_apk.json'
    )
    with open(data_path, 'r') as f:
        return json.load(f)

@pytest.fixture
def mock_mobsf_client():
    """MobSF 클라이언트 목업"""
    client = Mock()
    client.analyze_dex.return_value = {
        "status": "success",
        "dex_analysis": {}
    }
    client.analyze_behavior.return_value = {
        "status": "success",
        "behavior_analysis": {}
    }
    return client

@pytest.fixture
def sample_apk_path():
    """테스트용 APK 파일 경로"""
    return os.path.join(
        os.path.dirname(__file__),
        'test_data',
        'sample.apk'
    )

@pytest.fixture(autouse=True)
def mock_environment(monkeypatch):
    """테스트 환경 설정"""
    monkeypatch.setenv("MOBSF_API_KEY", "test_api_key")
    monkeypatch.setenv("MOBSF_SERVER", "http://localhost:8000")