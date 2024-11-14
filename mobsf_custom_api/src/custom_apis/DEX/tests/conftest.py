import json
import os

import pytest


@pytest.fixture
def sample_dex_data():
    """테스트용 DEX 데이터"""
    return b'dex\n035\0' + b'\x00' * 100

@pytest.fixture
def encrypted_dex_data():
    """암호화된 DEX 데이터"""
    return b'\x12\x34\x56' * 100

@pytest.fixture
def mock_dex_response():
    """목업 DEX 분석 응답"""
    return {
        "status": "success",
        "dex_files": [
            {
                "name": "classes.dex",
                "size": 1000,
                "is_encrypted": False
            },
            {
                "name": "classes2.dex",
                "size": 2000,
                "is_encrypted": True,
                "encryption_type": "AES-128/ECB"
            }
        ]
    }

@pytest.fixture
def dex_analysis_schema():
    """DEX 분석 스키마"""
    schema_path = os.path.join(
        os.path.dirname(__file__),
        '..',
        'dex_analysis_encrypted.json'
    )
    with open(schema_path, 'r') as f:
        return json.load(f)