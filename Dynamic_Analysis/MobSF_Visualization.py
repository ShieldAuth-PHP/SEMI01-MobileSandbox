import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# MobSF 설정
MOBSF_API_KEY = ""  # MobSF의 API 키를 여기에 입력
MOBSF_BASE_URL = "http://localhost:8000"  # MobSF 서버 URL

class MobSFClient:
    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.headers = {
            "Authorization": api_key,
        }
    
    async def get_report(self, analysis_id: str, report_type: str) -> dict:
        """MobSF에서 분석 리포트 가져오기"""
        endpoint = f"/api/v1/{report_type}/report_json"
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = requests.post(
                url,
                headers=self.headers,
                json={"hash": analysis_id}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to fetch report from MobSF: {str(e)}"
            )

# 전역 MobSF 클라이언트 인스턴스
mobsf_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup 이벤트
    global mobsf_client
    mobsf_client = MobSFClient(MOBSF_API_KEY, MOBSF_BASE_URL)
    yield
    # shutdown 이벤트
    mobsf_client = None

# FastAPI 앱 인스턴스 생성 시 lifespan 이벤트 핸들러 지정
app = FastAPI(
    title="MobSF Visualization API",
    lifespan=lifespan
)

class VisualizationRequest(BaseModel):
    analysis_id: str
    report_type: str  # 'static', 'dynamic', 'combined'
    visualization_type: str  # 'permissions', 'security_score', 'api_calls', 'network', 'components'

class SecurityMetrics:
    def __init__(self, report_data: dict):
        self.data = report_data
        
    def get_permission_analysis(self) -> dict:
        """권한 분석 데이터 추출"""
        permissions = self.data.get('permissions', {})
        return {
            'status': 'critical',
            'dangerous': len(permissions.get('dangerous_permissions', [])),
            'normal': len(permissions.get('normal_permissions', [])),
            'details': permissions
        }
        
    def get_security_score(self) -> dict:
        """보안 점수 계산"""
        security_score = self.data.get('security_score', {})
        return {
            'overall_score': security_score.get('score', 0),
            'categories': {
                'permissions': security_score.get('permissions_score', 0),
                'code_security': security_score.get('code_security_score', 0),
                'network_security': security_score.get('network_security_score', 0),
                'privacy': security_score.get('privacy_score', 0)
            }
        }

class VisualizationGenerator:
    @staticmethod
    def create_permissions_chart(metrics: SecurityMetrics) -> dict:
        """권한 분석 차트 생성"""
        perm_data = metrics.get_permission_analysis()
        
        fig = go.Figure(data=[
            go.Bar(
                name='Permissions',
                x=['Dangerous', 'Normal'],
                y=[perm_data['dangerous'], perm_data['normal']],
                marker_color=['red', 'green']
            )
        ])
        
        fig.update_layout(
            title='Permission Analysis',
            xaxis_title='Permission Type',
            yaxis_title='Count',
            template='plotly_white'
        )
        
        return fig.to_dict()
    
    @staticmethod
    def create_security_score_radar(metrics: SecurityMetrics) -> dict:
        """보안 점수 레이더 차트 생성"""
        score_data = metrics.get_security_score()
        
        categories = list(score_data['categories'].keys())
        values = list(score_data['categories'].values())
        
        fig = go.Figure(data=go.Scatterpolar(
            r=values,
            theta=categories,
            fill='toself'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100]
                )
            ),
            showlegend=False,
            title='Security Score Analysis'
        )
        
        return fig.to_dict()

@app.post("/api/v1/visualize")
async def create_visualization(request: VisualizationRequest):
    if mobsf_client is None:
        raise HTTPException(
            status_code=500,
            detail="MobSF client is not initialized"
        )
    
    try:
        # MobSF에서 분석 결과 가져오기
        report_data = await mobsf_client.get_report(
            request.analysis_id,
            request.report_type
        )
        
        # 메트릭스 계산
        metrics = SecurityMetrics(report_data)
        
        # 시각화 생성
        viz_generator = VisualizationGenerator()
        
        if request.visualization_type == 'permissions':
            chart_data = viz_generator.create_permissions_chart(metrics)
        elif request.visualization_type == 'security_score':
            chart_data = viz_generator.create_security_score_radar(metrics)
        else:
            raise HTTPException(status_code=400, detail="Unsupported visualization type")
            
        return JSONResponse(content={"chart_data": chart_data})
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/visualization_pdf")
async def generate_visualization_pdf(request: VisualizationRequest):
    if mobsf_client is None:
        raise HTTPException(
            status_code=500,
            detail="MobSF client is not initialized"
        )
    
    try:
        # 모든 시각화 생성
        visualizations = {}
        report_data = await mobsf_client.get_report(
            request.analysis_id,
            request.report_type
        )
        metrics = SecurityMetrics(report_data)
        viz_generator = VisualizationGenerator()
        
        # 모든 차트 생성
        visualizations['permissions'] = viz_generator.create_permissions_chart(metrics)
        visualizations['security_score'] = viz_generator.create_security_score_radar(metrics)
        
        # PDF 생성
        pdf_path = generate_pdf_report(visualizations, report_data)
        
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=f'security_analysis_{request.analysis_id}.pdf'
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def generate_pdf_report(visualizations: Dict, report_data: Dict) -> str:
    """PDF 리포트 생성"""
    # PDF 생성 로직 구현
    # 실제 구현 필요
    pass

# 서버 상태 확인 엔드포인트 추가
@app.get("/health")
async def health_check():
    return {"status": "healthy", "mobsf_client": "initialized" if mobsf_client else "not initialized"}

if __name__ == "__main__":
    import uvicorn

    # 서버 실행
    uvicorn.run(app, host="0.0.0.0", port=8000)