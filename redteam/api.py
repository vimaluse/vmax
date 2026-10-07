"""
Red Teaming API
FastAPI endpoints for running red team assessments via HTTP
"""

from typing import List, Optional, Dict
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import uuid

from .config import RedTeamConfig, AttackType
from .engine import RedTeamEngine
from .attacks import AttackGenerator
from .scenarios import ScenarioBuilder
from .report import RedTeamReport


# ============================================================
# PYDANTIC MODELS
# ============================================================

class RedTeamRequest(BaseModel):
    """Request to start red team assessment"""
    
    target_api_url: str = Field(
        default="http://localhost:8000",
        description="Target chatbot API URL"
    )
    
    attack_types: Optional[List[str]] = Field(
        default=None,
        description="Specific attack types to test"
    )
    
    max_attacks_per_type: int = Field(
        default=5,
        description="Maximum number of attacks per type"
    )
    
    parallel: bool = Field(
        default=True,
        description="Execute attacks in parallel"
    )
    
    include_scenarios: bool = Field(
        default=True,
        description="Include scenario-based attacks"
    )


class AttackTestRequest(BaseModel):
    """Request to test a single attack"""
    
    message: str = Field(
        ...,
        description="The attack payload/message"
    )
    
    attack_type: str = Field(
        default="prompt_injection",
        description="Type of attack"
    )
    
    conversation_history: Optional[List[Dict]] = Field(
        default=None,
        description="Conversation context"
    )


class RedTeamResponse(BaseModel):
    """Response from red team assessment"""
    
    assessment_id: str
    status: str
    total_attacks: int
    attacks_completed: int
    results_url: Optional[str] = None


class AttackTestResponse(BaseModel):
    """Response from single attack test"""
    
    attack_id: str
    was_blocked: bool
    response: str
    risk_score: float
    execution_time_ms: float


# ============================================================
# API ROUTER
# ============================================================

router = APIRouter(prefix="/api/redteam", tags=["red-team"])

# Store for tracking assessments
active_assessments: Dict[str, Dict] = {}


# ============================================================
# ENDPOINTS
# ============================================================

@router.get("/health")
async def redteam_health():
    """Health check for red teaming API"""
    
    return {
        "status": "healthy",
        "version": "1.0.0",
        "features": [
            "prompt_injection",
            "jailbreak",
            "hallucination",
            "toxicity",
            "data_leakage",
            "rag_poisoning",
            "bias",
            "logic_contradiction"
        ]
    }


@router.post("/assess")
async def start_assessment(
    request: RedTeamRequest,
    background_tasks: BackgroundTasks
):
    """
    Start a red team assessment
    Returns immediately with assessment ID for tracking
    """
    
    assessment_id = str(uuid.uuid4())
    
    # Store assessment metadata
    active_assessments[assessment_id] = {
        "status": "running",
        "created_at": __import__("datetime").datetime.now().isoformat(),
        "config": {
            "target_url": request.target_api_url,
            "attack_types": request.attack_types,
            "max_attacks": request.max_attacks_per_type,
            "parallel": request.parallel,
            "include_scenarios": request.include_scenarios
        },
        "progress": {
            "total_attacks": 0,
            "completed": 0,
            "bypasses_found": 0
        }
    }
    
    # Run assessment in background
    background_tasks.add_task(
        _run_assessment,
        assessment_id,
        request
    )
    
    return {
        "assessment_id": assessment_id,
        "status": "started",
        "message": "Red team assessment initiated. Check status endpoint for progress.",
        "status_url": f"/api/redteam/status/{assessment_id}"
    }


@router.get("/status/{assessment_id}")
async def get_assessment_status(assessment_id: str):
    """Get status of a running red team assessment"""
    
    if assessment_id not in active_assessments:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found"
        )
    
    assessment = active_assessments[assessment_id]
    
    return {
        "assessment_id": assessment_id,
        "status": assessment["status"],
        "progress": assessment.get("progress", {}),
        "results_available": assessment["status"] == "completed"
    }


@router.get("/results/{assessment_id}")
async def get_assessment_results(assessment_id: str):
    """Get results of a completed assessment"""
    
    if assessment_id not in active_assessments:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found"
        )
    
    assessment = active_assessments[assessment_id]
    
    if assessment["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Assessment status is {assessment['status']}, not completed"
        )
    
    return assessment.get("results", {})


@router.post("/test-attack")
async def test_single_attack(request: AttackTestRequest):
    """
    Test a single attack payload
    Useful for quick testing of specific payloads
    """
    
    # Map attack type
    try:
        attack_type = AttackType[request.attack_type.upper()]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack type: {request.attack_type}"
        )
    
    config = RedTeamConfig()
    
    try:
        async with RedTeamEngine(config) as engine:
            
            # Create attack payload from request
            from .config import AttackPayload, SeverityLevel
            
            payload = AttackPayload(
                attack_type=attack_type,
                message=request.message,
                description="Single attack test",
                expected_block=True,
                severity=SeverityLevel.MEDIUM
            )
            
            # Execute attack
            import time
            start_time = time.time()
            
            was_blocked, response, metadata = await engine.execute_attack(
                payload,
                request.conversation_history
            )
            
            execution_time = time.time() - start_time
            
            return AttackTestResponse(
                attack_id=str(uuid.uuid4())[:8],
                was_blocked=was_blocked,
                response=response[:500],  # Truncate
                risk_score=0.5 if was_blocked else 0.9,
                execution_time_ms=round(execution_time * 1000, 2)
            )
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Attack execution failed: {str(e)}"
        )


@router.get("/attacks/{attack_type}")
async def list_attack_payloads(attack_type: str, limit: int = 10):
    """List available attack payloads for a specific type"""
    
    # Map attack type
    try:
        atype = AttackType[attack_type.upper()]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack type: {attack_type}"
        )
    
    generator = AttackGenerator()
    
    # Get payloads
    sample = generator.sample_attacks(atype, limit)
    
    return {
        "attack_type": attack_type,
        "count": len(sample),
        "payloads": [p.to_dict() for p in sample]
    }


@router.get("/scenarios")
async def list_scenarios():
    """List available attack scenarios"""
    
    builder = ScenarioBuilder()
    scenarios = builder.get_all_scenarios()
    
    return {
        "total": len(scenarios),
        "scenarios": [s.to_dict() for s in scenarios]
    }


@router.get("/scenarios/{difficulty}")
async def list_scenarios_by_difficulty(difficulty: str):
    """List scenarios filtered by difficulty"""
    
    valid_difficulties = ["easy", "medium", "hard"]
    
    if difficulty not in valid_difficulties:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid difficulty. Must be one of: {valid_difficulties}"
        )
    
    builder = ScenarioBuilder()
    scenarios = builder.get_scenario_by_difficulty(difficulty)
    
    return {
        "difficulty": difficulty,
        "count": len(scenarios),
        "scenarios": [s.to_dict() for s in scenarios]
    }


@router.post("/generate-report/{assessment_id}")
async def generate_report(
    assessment_id: str,
    format: str = "json"
):
    """
    Generate report in specified format
    Formats: json, markdown, html
    """
    
    if assessment_id not in active_assessments:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found"
        )
    
    assessment = active_assessments[assessment_id]
    
    if assessment["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail="Assessment must be completed before generating report"
        )
    
    # Get results
    results = assessment.get("results", {}).get("results", [])
    
    if not results:
        raise HTTPException(
            status_code=400,
            detail="No results available to report"
        )
    
    # Convert to EvaluationResult objects
    from .config import EvaluationResult
    
    eval_results = [
        EvaluationResult(**r) if isinstance(r, dict) else r
        for r in results
    ]
    
    # Generate report
    report = RedTeamReport(eval_results)
    
    try:
        if format == "json":
            filepath = report.generate_json_report()
        elif format == "markdown":
            filepath = report.generate_markdown_report()
        elif format == "html":
            filepath = report.generate_html_report()
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format: {format}"
            )
        
        return {
            "status": "success",
            "format": format,
            "filepath": str(filepath)
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {str(e)}"
        )


# ============================================================
# BACKGROUND TASK
# ============================================================

async def _run_assessment(assessment_id: str, request: RedTeamRequest):
    """Background task to run the actual assessment"""
    
    try:
        assessment = active_assessments[assessment_id]
        
        # Create config
        config = RedTeamConfig(
            api_url=request.target_api_url,
            variations_per_attack=request.max_attacks_per_type
        )
        
        # Filter attack types if specified
        if request.attack_types:
            try:
                enabled = [
                    AttackType[t.upper()]
                    for t in request.attack_types
                ]
                config.enabled_attacks = enabled
            except KeyError as e:
                assessment["status"] = "failed"
                assessment["error"] = f"Invalid attack type: {e}"
                return
        
        # Run assessment
        async with RedTeamEngine(config) as engine:
            results = await engine.run_full_red_team()
            
            # Update assessment
            assessment["status"] = "completed"
            assessment["results"] = results
            assessment["progress"]["total_attacks"] = results.get("total_attacks", 0)
            assessment["progress"]["completed"] = results.get("total_attacks", 0)
            assessment["progress"]["bypasses_found"] = results.get("total_bypassed", 0)
    
    except Exception as e:
        assessment = active_assessments.get(assessment_id)
        if assessment:
            assessment["status"] = "failed"
            assessment["error"] = str(e)


# ============================================================
# INCLUDE IN MAIN APP
# ============================================================

def include_redteam_routes(app):
    """
    Include red teaming routes in main FastAPI app
    
    Usage in main.py:
        from redteam.api import include_redteam_routes
        include_redteam_routes(app)
    """
    
    app.include_router(router)
