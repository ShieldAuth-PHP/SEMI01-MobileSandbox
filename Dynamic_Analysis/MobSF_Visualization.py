import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from io import BytesIO
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import plotly
import plotly.express as px
import plotly.graph_objects as go
import requests
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (Image, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

# MobSF 설정
MOBSF_API_KEY = ""  # MobSF의 API 키를 여기에 입력
MOBSF_BASE_URL = "http://localhost:8000"  # MobSF 서버 URL

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

class PDFReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """커스텀 스타일 설정"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#34495e')
        ))

    def _save_chart_as_image(self, chart_data: dict, width: int = 800, height: int = 400) -> BytesIO:
        """Plotly 차트를 이미지로 변환"""
        fig = plotly.graph_objects.Figure(chart_data)
        img_bytes = fig.to_image(format="png", width=width, height=height)
        return BytesIO(img_bytes)

    def _create_summary_table(self, metrics: SecurityMetrics) -> Table:
        """보안 분석 요약 테이블 생성"""
        perm_data = metrics.get_permission_analysis()
        score_data = metrics.get_security_score()
        
        data = [
            ['Metric', 'Value'],
            ['Overall Security Score', f"{score_data['overall_score']}%"],
            ['Permission Risk', f"{score_data['categories']['permissions']}%"],
            ['Code Security', f"{score_data['categories']['code_security']}%"],
            ['Network Security', f"{score_data['categories']['network_security']}%"],
            ['Privacy Score', f"{score_data['categories']['privacy']}%"],
            ['Dangerous Permissions', str(perm_data['dangerous'])],
            ['Normal Permissions', str(perm_data['normal'])],
        ]
        
        table = Table(data, colWidths=[2.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
        ]))
        
        return table

    def generate(self, visualizations: Dict, metrics: SecurityMetrics, analysis_id: str) -> str:
        """PDF 보고서 생성"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(self.output_dir, f"security_analysis_{analysis_id}_{timestamp}.pdf")
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        story = []
        
        # 제목 추가
        title = Paragraph(
            "Mobile Application Security Analysis Report",
            self.styles['CustomTitle']
        )
        story.append(title)
        
        # 메타데이터 추가
        story.append(Paragraph(f"Analysis ID: {analysis_id}", self.styles['Normal']))
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # 요약 섹션
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(self._create_summary_table(metrics))
        story.append(Spacer(1, 20))
        
        # 차트 섹션들
        if 'permissions' in visualizations:
            story.append(Paragraph("Permission Analysis", self.styles['SectionHeader']))
            img_data = self._save_chart_as_image(visualizations['permissions'])
            img = Image(img_data, width=6*inch, height=3*inch)
            story.append(img)
            story.append(Spacer(1, 20))
        
        if 'security_score' in visualizations:
            story.append(Paragraph("Security Score Analysis", self.styles['SectionHeader']))
            img_data = self._save_chart_as_image(visualizations['security_score'])
            img = Image(img_data, width=6*inch, height=3*inch)
            story.append(img)
            story.append(Spacer(1, 20))
        
        # 상세 권한 정보
        perm_data = metrics.get_permission_analysis()
        details = perm_data.get('details', {})
        
        if details:
            story.append(Paragraph("Detailed Permission Analysis", self.styles['SectionHeader']))
            
            if details.get('dangerous_permissions'):
                story.append(Paragraph("Dangerous Permissions:", self.styles['Heading4']))
                for perm in details['dangerous_permissions']:
                    story.append(Paragraph(f"• {perm}", self.styles['Normal']))
                story.append(Spacer(1, 10))
            
            if details.get('normal_permissions'):
                story.append(Paragraph("Normal Permissions:", self.styles['Heading4']))
                for perm in details['normal_permissions'][:10]:
                    story.append(Paragraph(f"• {perm}", self.styles['Normal']))
                if len(details['normal_permissions']) > 10:
                    story.append(Paragraph(f"... and {len(details['normal_permissions']) - 10} more", self.styles['Normal']))
        
        # PDF 생성
        doc.build(story)
        return output_path

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

# FastAPI 앱 인스턴스 생성
app = FastAPI(
    title="MobSF Visualization API",
    lifespan=lifespan
)

class VisualizationRequest(BaseModel):
    analysis_id: str
    report_type: str  # 'static', 'dynamic', 'combined'
    visualization_type: str  # 'permissions', 'security_score', 'api_calls', 'network', 'components'

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
        report_data = await mobsf_client.get_report(
            request.analysis_id,
            request.report_type
        )
        metrics = SecurityMetrics(report_data)
        viz_generator = VisualizationGenerator()
        
        visualizations = {
            'permissions': viz_generator.create_permissions_chart(metrics),
            'security_score': viz_generator.create_security_score_radar(metrics)
        }
        
        # PDF 생성
        pdf_generator = PDFReportGenerator()
        pdf_path = pdf_generator.generate(visualizations, metrics, request.analysis_id)
        
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=f'security_analysis_{request.analysis_id}.pdf'
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 서버 상태 확인 엔드포인트
@app.get("/health")
async def health_check():
    return {"status": "healthy", "mobsf_client": "initialized" if mobsf_client else "not initialized"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)