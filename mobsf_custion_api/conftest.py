import os
import sys

import pytest

# 프로젝트 루트 디렉토리를 Python 경로에 추가
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# 공통으로 사용할 fixture
@pytest.fixture(scope="session")
def test_api_key():
    """테스트용 API 키"""
    return "test_api_key_12345"

@pytest.fixture(scope="session")
def test_server_url():
    """테스트용 서버 URL"""
    return "http://localhost:8000"