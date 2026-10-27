"""
Routes API pour le système Multi-Agent IA
Endpoints pour le brainstorming collaboratif d'équipe
"""

from fastapi import APIRouter, HTTPException
try:
    import orjson as _orjson  # noqa: F401
    from fastapi.responses import ORJSONResponse as JSONResponse
except ImportError:  # pragma: no cover
    from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.services.agent_team_service import team_service
from app.services.storage_service import storage_service
from app.services.ai_analysis_service import ai_service
from app.core.logging_config import get_logger

logger = get_logger(__name__)

team_router = APIRouter(prefix="/api", tags=["Team AI"])


class AgentChatRequest(BaseModel):
    message: str
    agent: str


@team_router.get("/team/agents")
async def list_agents():
    """Liste tous les agents disponibles avec leurs rôles"""
    return {
        "agents": team_service.get_agents_info(),
        "ai_available": team_service.is_available()
    }


@team_router.get("/analysis/{task_id}/team-analysis")
def run_team_analysis(task_id: str):
    """
    Lance l'analyse complète par l'équipe de 4 agents.
    Chaque agent collabore séquentiellement.
    """
    logger.info(f"🧠 Lancement Team Analysis pour task_id: {task_id}")
    
    try:
        # Vérifier disponibilité Ollama
        if not team_service.is_available():
            msg = "Service Ollama non disponible. Démarrez Ollama avec: OLLAMA_HOST=0.0.0.0:11434 ollama serve"
            return JSONResponse(content={
                "task_id": task_id,
                "success": False,
                "ai_available": False,
                "error": msg,
                "structured": ai_service.extract_structured_response(msg)
            })
        
        # Charger les résultats d'analyse
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(
                status_code=404,
                detail=f"Résultats non trouvés pour task_id: {task_id}"
            )
        
        # Lancer l'équipe complète
        team_results = team_service.run_full_team(results)
        
        return JSONResponse(content={
            "task_id": task_id,
            "ai_available": True,
            **team_results,
            "generated_at": datetime.now().isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 Erreur Team Analysis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erreur serveur: {str(e)}")


@team_router.get("/analysis/{task_id}/agent/{agent_name}")
def run_single_agent(task_id: str, agent_name: str):
    """
    Lance un agent spécifique sur les résultats d'analyse.
    Agents: brainstormer, chef_projet, programmeur, validateur
    """
    logger.info(f"🤖 Lancement agent '{agent_name}' pour task_id: {task_id}")
    
    try:
        if not team_service.is_available():
            msg = "Service Ollama non disponible"
            return JSONResponse(content={
                "success": False,
                "error": msg,
                "structured": ai_service.extract_structured_response(msg)
            })
        
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        agent_result = team_service.run_single_agent(agent_name, results)
        
        return JSONResponse(content={
            "task_id": task_id,
            **agent_result,
            "generated_at": datetime.now().isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur agent: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@team_router.post("/analysis/{task_id}/agent-chat")
def chat_with_agent(task_id: str, request: AgentChatRequest):
    """
    Chat interactif avec un agent spécifique.
    Permet de poser des questions ciblées à un agent.
    """
    logger.info(f"💬 Chat agent '{request.agent}' pour task_id: {task_id}")
    
    try:
        if not team_service.is_available():
            msg = "Service Ollama non disponible"
            return JSONResponse(content={
                "success": False,
                "error": msg,
                "structured": ai_service.extract_structured_response(msg)
            })
        
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        chat_result = team_service.chat_with_agent(
            request.agent, 
            request.message, 
            results
        )
        
        return JSONResponse(content={
            "task_id": task_id,
            **chat_result,
            "timestamp": datetime.now().isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur chat agent: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
