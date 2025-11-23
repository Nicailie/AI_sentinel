"""
AI Sentinel - Unified API with Intent Analysis
FIXED: Now includes jailbreak detection!
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import uvicorn
from datetime import datetime

# Import ALL detectors including intent analyzer
from models.bio_detector import BioThreatDetector
from models.cyber_detector import CyberThreatDetector
from models.intent_analyzer import IntentAnalyzer

# Initialize FastAPI
app = FastAPI(
    title="AI Sentinel",
    description="Dual-layer threat detection with jailbreak protection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize ALL detectors
bio_detector = BioThreatDetector()
cyber_detector = CyberThreatDetector()
intent_analyzer = IntentAnalyzer()  # CRITICAL: This was missing!

threat_log = []

# ==================== Models ====================

class AnalysisRequest(BaseModel):
    content: str = Field(..., description="Content to analyze")
    context: Optional[str] = Field(None, description="Additional context")
    source: Optional[str] = Field("api", description="Source of content")

class LayerResult(BaseModel):
    risk_score: float
    risk_level: str
    flags: List[Dict]
    summary: str
    recommendations: List[str]
    mitre_techniques: Optional[List[str]] = None

class IntentResult(BaseModel):
    manipulation_detected: bool
    manipulation_score: float
    risk_multiplier: float
    flags: List[Dict]
    summary: str
    trust_assessment: str
    recommendations: List[str]

class AnalysisResponse(BaseModel):
    timestamp: str
    overall_risk_score: float
    overall_risk_level: str
    bio_analysis: LayerResult
    cyber_analysis: LayerResult
    intent_analysis: IntentResult  # NEW!
    combined_flags: List[Dict]
    priority_actions: List[str]
    deployment_recommendations: List[str]

class StatsResponse(BaseModel):
    total_analyses: int
    bio_threats_detected: int
    cyber_threats_detected: int
    jailbreak_attempts_detected: int  # NEW!
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int

# ==================== Helper Functions ====================

def calculate_overall_risk(
    bio_score: float, 
    cyber_score: float, 
    manipulation_score: float,
    risk_multiplier: float
) -> tuple:
    """
    FIXED: Use MAX score approach - if ANY domain is HIGH, overall is HIGH
    This prevents dilution of serious threats
    """
    # Use the MAXIMUM of bio/cyber scores as base (don't average!)
    base_score = max(bio_score, cyber_score)
    
    # Add manipulation score weighted at 20%
    base_score = max(base_score, base_score + (manipulation_score * 0.2))
    
    # Apply risk multiplier from intent analysis
    adjusted_score = base_score * risk_multiplier
    
    # Cap at 100
    overall_score = min(100.0, adjusted_score)
    
    # Determine level - use LOWER thresholds to match detector thresholds
    if overall_score >= 55:  # Match detector HIGH threshold
        level = "CRITICAL" if risk_multiplier > 1.3 else "HIGH"
    elif overall_score >= 28:  # Match detector MEDIUM threshold
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return overall_score, level

def generate_priority_actions(
    bio_flags: List[Dict], 
    cyber_flags: List[Dict],
    intent_flags: List[Dict],  # NEW!
    risk_multiplier: float
) -> List[str]:
    """Generate prioritized actions including jailbreak response"""
    actions = []
    
    # Check for jailbreak attempts FIRST (highest priority)
    has_jailbreak = any(f['type'] == 'jailbreak' for f in intent_flags)
    has_suspicious_combo = any(f['type'] == 'suspicious_combination' for f in intent_flags)
    
    if has_suspicious_combo:
        actions.append("🚨 CRITICAL ALERT: Jailbreak attempt with dangerous content detected")
        actions.append("🛑 BLOCK IMMEDIATELY - Do not process request")
        actions.append("📝 Document attempt and flag requester")
    elif has_jailbreak and risk_multiplier > 1.2:
        actions.append("⚠️ SUSPICIOUS: Possible bypass attempt detected")
        actions.append("👤 Require human verification before proceeding")
    
    # Check bio/cyber threats
    high_bio = any(f['severity'] == 'high' for f in bio_flags)
    high_cyber = any(f['severity'] == 'high' for f in cyber_flags)
    
    if high_bio and high_cyber:
        actions.append("🔴 CRITICAL: Multi-domain threats detected")
        actions.append("👥 Immediate expert review required")
    elif high_bio:
        actions.append("🧬 HIGH PRIORITY: Biosecurity threat - flag for expert review")
    elif high_cyber:
        actions.append("💻 HIGH PRIORITY: Cybersecurity threat - alert security team")
    
    # Specific recommendations
    bio_types = set(f['type'] for f in bio_flags)
    cyber_types = set(f['type'] for f in cyber_flags)
    
    if 'sequence' in bio_types:
        actions.append("🧪 Screen sequences through Common Mechanism/SecureDNA")
    
    if 'pathogen' in bio_types:
        actions.append("📋 Verify institutional oversight and authorization")
    
    if 'exploit' in cyber_types:
        actions.append("🚫 Block execution and scan with vulnerability tools")
    
    if 'malware' in cyber_types:
        actions.append("🔒 Quarantine and analyze in sandbox")
    
    if not actions:
        actions.append("✅ Content appears safe - proceed normally")
    
    return actions

def generate_deployment_recommendations(
    bio_score: float, 
    cyber_score: float,
    manipulation_score: float
) -> List[str]:
    """Deployment recommendations"""
    recommendations = []
    
    if manipulation_score > 30:
        recommendations.append("Deploy with strict jailbreak monitoring enabled")
        recommendations.append("Implement user reputation scoring system")
    
    if bio_score > 40 or cyber_score > 40:
        recommendations.append("Deploy as API gateway middleware")
        recommendations.append("Integrate with IRB workflows")
    
    if cyber_score > 40:
        recommendations.append("Deploy in SOC for threat monitoring")
        recommendations.append("Integrate with SIEM platforms")
    
    if bio_score > 40:
        recommendations.append("Integrate with DNA synthesis screening")
        recommendations.append("Deploy at research institution checkpoints")
    
    recommendations.append("Deploy as IDE plugin for real-time review")
    recommendations.append("Implement as pre-commit hook in version control")
    
    return recommendations

# ==================== API Endpoints ====================

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "AI Sentinel",
        "version": "1.0.0",
        "capabilities": [
            "biosecurity_detection",
            "cybersecurity_detection",
            "jailbreak_detection"  # NEW!
        ],
        "docs": "/docs"
    }

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_content(request: AnalysisRequest):
    """
    FIXED: Now includes intent analysis for jailbreak detection
    """
    try:
        timestamp = datetime.now().isoformat()
        
        # Run bio and cyber detectors first
        bio_result = bio_detector.analyze(request.content)
        cyber_result = cyber_detector.analyze(request.content)
        
        # CRITICAL: Run intent analyzer with bio/cyber context
        intent_result = intent_analyzer.analyze(
            request.content,
            bio_flags=bio_result['flags'],
            cyber_flags=cyber_result['flags']
        )
        
        # Calculate overall risk (NOW includes intent analysis)
        overall_score, overall_level = calculate_overall_risk(
            bio_result['risk_score'],
            cyber_result['risk_score'],
            intent_result['manipulation_score'],
            intent_result['risk_multiplier']
        )
        
        # Combine all flags
        all_flags = (
            bio_result['flags'] + 
            cyber_result['flags'] + 
            intent_result['flags']
        )
        
        # Generate priority actions (including jailbreak response)
        priority_actions = generate_priority_actions(
            bio_result['flags'],
            cyber_result['flags'],
            intent_result['flags'],
            intent_result['risk_multiplier']
        )
        
        # Deployment recommendations
        deployment_recs = generate_deployment_recommendations(
            bio_result['risk_score'],
            cyber_result['risk_score'],
            intent_result['manipulation_score']
        )
        
        # Build response
        response = AnalysisResponse(
            timestamp=timestamp,
            overall_risk_score=overall_score,
            overall_risk_level=overall_level,
            bio_analysis=LayerResult(**bio_result),
            cyber_analysis=LayerResult(**cyber_result),
            intent_analysis=IntentResult(**intent_result),  # NEW!
            combined_flags=all_flags,
            priority_actions=priority_actions,
            deployment_recommendations=deployment_recs
        )
        
        # Log the analysis
        threat_log.append({
            'timestamp': timestamp,
            'risk_level': overall_level,
            'bio_score': bio_result['risk_score'],
            'cyber_score': cyber_result['risk_score'],
            'manipulation_score': intent_result['manipulation_score'],
            'jailbreak_detected': intent_result['manipulation_detected'],
            'source': request.source
        })
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/stats", response_model=StatsResponse)
async def get_statistics():
    """System statistics including jailbreak attempts"""
    if not threat_log:
        return StatsResponse(
            total_analyses=0,
            bio_threats_detected=0,
            cyber_threats_detected=0,
            jailbreak_attempts_detected=0,
            high_risk_count=0,
            medium_risk_count=0,
            low_risk_count=0
        )
    
    total = len(threat_log)
    bio_threats = sum(1 for log in threat_log if log['bio_score'] > 40)
    cyber_threats = sum(1 for log in threat_log if log['cyber_score'] > 40)
    jailbreak_attempts = sum(1 for log in threat_log if log.get('jailbreak_detected', False))
    
    high_risk = sum(1 for log in threat_log if log['risk_level'] in ['HIGH', 'CRITICAL'])
    medium_risk = sum(1 for log in threat_log if log['risk_level'] == 'MEDIUM')
    low_risk = sum(1 for log in threat_log if log['risk_level'] == 'LOW')
    
    return StatsResponse(
        total_analyses=total,
        bio_threats_detected=bio_threats,
        cyber_threats_detected=cyber_threats,
        jailbreak_attempts_detected=jailbreak_attempts,
        high_risk_count=high_risk,
        medium_risk_count=medium_risk,
        low_risk_count=low_risk
    )

@app.get("/logs")
async def get_threat_logs(limit: int = 50):
    return {
        "total_logs": len(threat_log),
        "recent_logs": threat_log[-limit:] if threat_log else []
    }

@app.post("/batch-analyze")
async def batch_analyze(contents: List[str]):
    """Batch analysis"""
    results = []
    
    for content in contents:
        request = AnalysisRequest(content=content, source="batch")
        result = await analyze_content(request)
        results.append(result)
    
    return {
        "total_analyzed": len(contents),
        "results": results
    }

# ==================== Main ====================

if __name__ == "__main__":
    print("=" * 80)
    print("🛡️  AI SENTINEL - Dual-Layer Threat Detection System")
    print("=" * 80)
    print("\n✅ Bio Detector: LOADED")
    print("✅ Cyber Detector: LOADED")
    print("✅ Intent Analyzer: LOADED")
    print("\n🚀 Starting API server...")
    print("📡 API Documentation: http://localhost:8000/docs")
    print("📊 Interactive API: http://localhost:8000/redoc")
    print("\n🔍 Ready to detect bio, cyber, and jailbreak threats!\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )