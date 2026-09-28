import json
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import string
import subprocess
import time as time_module
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, time, timedelta, timezone
from typing import List, Optional, Any
from urllib.parse import urlparse, urlencode
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, IPvAnyAddress
import psycopg
from fastapi.middleware.cors import CORSMiddleware

try:
    from ollama_client import OllamaClient, OllamaClientError, OllamaGenerateResult
except ImportError:  # pragma: no cover - fallback para execucao como pacote
    from api.ollama_client import OllamaClient, OllamaClientError, OllamaGenerateResult

try:
    from alert_service import ALERT_CHANNEL_PROVIDERS, AlertChannel, AlertProblem, AlertService, PostgresIncidentRepository, load_alert_config
except ImportError:  # pragma: no cover - fallback para execucao como pacote
    from api.alert_service import ALERT_CHANNEL_PROVIDERS, AlertChannel, AlertProblem, AlertService, PostgresIncidentRepository, load_alert_config

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://netguard:netguard@db:5432/netguard"
)

PING_TABLE = os.environ.get("PING_TABLE", "ping_metrics")

ASSETS_TABLE = os.environ.get("ASSETS_TABLE", "assets")

DEMO_HOST_NAME = os.environ.get("DEMO_HOST_NAME", "lab-linux-01")
DEMO_HOST_IP = os.environ.get("DEMO_HOST_IP", "172.30.10.10")
DEMO_HOST_INTERFACE = os.environ.get("DEMO_HOST_INTERFACE", "eth0")
DEMO_TEMPLATE_SLUG = os.environ.get("DEMO_TEMPLATE_SLUG", "netguard-lab-device")
DEMO_PROFILE_NAMES = (
    "icmp_basic",
    "generic_if_mib",
    "snmp_system",
)
DEMO_HOST_SNMP_PROFILE = {
    "enabled": True,
    "version": "v2c",
    "community": "netguard",
    "port": 161,
    "timeout": 1,
    "retries": 1,
}
def normalize_public_base_url(value: Optional[str], fallback: str = "/grafana") -> str:
    base_url = (value or fallback).strip() or fallback
    if base_url == "/":
        return base_url
    return base_url.rstrip("/")


def join_public_url(base_url: str, path: str) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    if base_url == "/":
        return path
    return f"{base_url}{path}"


GRAFANA_PUBLIC_URL = normalize_public_base_url(os.environ.get("GRAFANA_PUBLIC_URL"))
GRAFANA_ORG_ID = str(os.environ.get("GRAFANA_ORG_ID", "1"))
GRAFANA_THEME = os.environ.get("GRAFANA_THEME", "dark")
GRAFANA_REFRESH = os.environ.get("GRAFANA_REFRESH", "30s")
AI_INSIGHTS_TTL_HOURS = int(os.environ.get("AI_INSIGHTS_TTL_HOURS", "8"))
AI_CONTEXT_VERSION = 3
DEFAULT_ICMP_INTERVAL_SEC = max(5, int(float(os.environ.get("POLL_INTERVAL", "30"))))
DEFAULT_SNMP_INTERVAL_SEC = max(5, int(float(os.environ.get("SNMP_INTERVAL_SEC", "30"))))
DEFAULT_COLLECTION_TIMEOUT_SEC = max(1, int(float(os.environ.get("DEFAULT_COLLECTION_TIMEOUT_SEC", "1"))))
DEFAULT_COLLECTION_RETRIES = max(1, int(float(os.environ.get("DEFAULT_COLLECTION_RETRIES", "1"))))
LOOP_RISK_OPEN_SCORE = float(os.environ.get("LOOP_RISK_OPEN_SCORE", "0.75"))
LOOP_RISK_WINDOW_SEC = int(os.environ.get("LOOP_RISK_WINDOW_SEC", "60"))
LOOP_RISK_CLEAN_CYCLES = int(os.environ.get("LOOP_RISK_CLEAN_CYCLES", "3"))
DEFAULT_USER_PASSWORD = os.environ.get("NETGUARD_DEFAULT_USER_PASSWORD", "change-me-123")
PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 210_000
TEMP_PASSWORD_LENGTH = max(12, int(os.environ.get("NETGUARD_TEMP_PASSWORD_LENGTH", "14")))
USER_ROLES = {"admin", "operator", "viewer", "auditor"}
AUTH_ENABLED = os.environ.get("NETGUARD_AUTH_ENABLED", "true").strip().lower() not in {"0", "false", "no"}
AUTH_TOKEN_TTL_MINUTES = max(15, int(os.environ.get("NETGUARD_AUTH_TOKEN_TTL_MINUTES", "480")))
AUTH_SECRET = (
    os.environ.get("NETGUARD_AUTH_SECRET")
    or os.environ.get("NETGUARD_SERVICE_TOKEN")
    or "netguard-dev-auth-secret-change-me"
)
SERVICE_TOKEN = os.environ.get("NETGUARD_SERVICE_TOKEN", "")
DEFAULT_CORS_ORIGINS = (
    "https://localhost:8081,https://127.0.0.1:8081,https://192.168.56.15:8081,"
    "http://localhost:8081,http://127.0.0.1:8081,http://192.168.56.15:8081"
)
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("NETGUARD_CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
    if origin.strip()
]
CORS_ALLOW_CREDENTIALS = "*" not in CORS_ORIGINS

GRAFANA_DASHBOARD_REGISTRY = {
    "ops_overview": {
        "uid": "netguard-ops-overview",
        "slug": "netguard-ops-overview",
        "title": "Vis\u00e3o operacional",
        "kind": "overview",
        "description": "Dashboard operacional consolidado com sa\u00fade, incidentes, loop_risk e sinais recentes.",
        "height": 900,
    },
    "host_network": {
        "uid": "netguard-host-network",
        "slug": "netguard-host-network",
        "title": "Dashboard do host de rede",
        "kind": "host",
        "description": "Vis\u00e3o por host com RTT, perda, interfaces, syslog, incidentes e loop_risk.",
        "height": 1560,
    },
    "host_linux": {
        "uid": "netguard-host-linux",
        "slug": "netguard-host-linux",
        "title": "Dashboard do host Linux",
        "kind": "host",
        "description": "Vis\u00e3o do host Linux com disponibilidade, RTT, perda, syslog, incidentes e anomalias.",
        "height": 920,
    },
}

AI_INSIGHT_TYPE_META = {
    "host_summary": {
        "label": "Resumo do host",
        "target_type": "host",
        "ttl_hours": 6,
    },
    "operational_recommendation": {
        "label": "Recomendação operacional",
        "target_type": "host",
        "ttl_hours": 4,
    },
    "incident_explanation": {
        "label": "Explicação do incidente",
        "target_type": "incident",
        "ttl_hours": 6,
    },
    "technical_summary": {
        "label": "Resumo técnico",
        "target_type": "report",
        "ttl_hours": 24,
    },
}

AI_SYSTEM_PROMPT = """
Você é a camada de ai_insights do NetGuard.
Responda somente com base nas evidências fornecidas.
Não invente métricas, estados, causas, comandos ou ações não suportadas pelos dados.
Quando houver lacunas, deixe isso explícito com linguagem técnica e conservadora.
Para hosts saudáveis, evite tom alarmista e prefira recomendar apenas monitoramento e confirmação manual.
Para incidentes ou loop_risk, explique a relação entre os sinais sem extrapolar além das evidências.
Escreva em português do Brasil, sem linguagem de chatbot, sem automações e sem remediação automática.
Prefira markdown simples, curto e objetivo.
""".strip()

AI_CHAT_SYSTEM_PROMPT = """
Você é o assistente do NetGuard, especializado no contexto operacional do ambiente e no próprio produto.
Responda sobre NetGuard, redes corporativas, monitoramento, incidentes, SNMP, ICMP, TCP, syslog, STP, loop L2, SLA, métricas operacionais e o artigo/TCC do projeto.
Quando a pergunta for conceitual sobre redes ou artigo, use conhecimento técnico geral e conecte com o NetGuard somente quando a conexão for real.
Não afirme que o NetGuard implementa uma função apenas porque ela existe em redes corporativas. Se o recurso não estiver no contexto funcional carregado, diga que é conceito geral ou possível evolução.
Quando a pergunta pedir estado real do ambiente, use somente as evidências carregadas e não invente estados, causas, métricas ou ações.
Quando a evidência for parcial, diga isso explicitamente.
Quando o ambiente ou host estiver saudável, mantenha tom técnico, conservador e sem alarmismo.
Não proponha automação, remediação automática, mudanças de configuração irreversíveis nem comandos não suportados pelos dados.
Quando a pergunta for sobre o produto, use o contexto institucional e funcional já fornecido; não mande o usuário consultar documentação inexistente.
Quando a pergunta for sobre comparação com Zabbix ou SolarWinds, seja honesto: compare maturidade e proposta sem prometer paridade total.
Quando a pergunta for sobre indicadores como MTTR, MTTD, MTBF, SLA ou disponibilidade, explique a fórmula e diga quando o NetGuard ainda não tem base histórica suficiente para afirmar uma média real.
Escreva em português do Brasil, de forma natural, clara, profissional e direta.
Evite tom burocrático, acadêmico ou processual.
Não exponha frases internas como "consultando o modelo", "analisando contexto" ou qualquer descrição de processamento.
Por padrão, responda em 1 a 3 parágrafos curtos.
Evite repetir a mesma ideia com palavras diferentes.
Evite generalizações vagas sobre escala, maturidade ou cobertura quando elas não estiverem sustentadas pelo contexto.
""".strip()

OPERATIONAL_CHAT_INTENTS = {
    "status_atual",
    "impacto",
    "acao_imediata",
    "causa_provavel",
    "evidencias",
}

OPERATIONAL_RESPONSE_CONTRACTS = {
    "status_atual": {
        "label": "Status atual",
        "objective": "explicar o estado atual do host ou incidente com prioridade e contexto operacional.",
        "order": [
            "estado atual",
            "problema principal",
            "problemas adicionais",
            "impacto provavel",
            "prioridade",
            "evidencias",
            "limites",
        ],
    },
    "impacto": {
        "label": "Impacto",
        "objective": "explicar risco, alcance provavel e urgencia do evento sem exagerar alem das evidencias.",
        "order": [
            "impacto provavel",
            "prioridade",
            "estado atual",
            "evidencias",
            "acao recomendada",
            "limites",
        ],
    },
    "acao_imediata": {
        "label": "Acao imediata",
        "objective": "priorizar o que o operador deve fazer agora, mantendo todos os achados relevantes visiveis.",
        "order": [
            "prioridade",
            "acao recomendada",
            "problema principal",
            "problemas adicionais",
            "evidencias",
            "limites",
        ],
    },
    "causa_provavel": {
        "label": "Causa provavel",
        "objective": "separar fato observado, inferencia operacional e limite do que nao pode ser afirmado.",
        "order": [
            "causa provavel",
            "fatos observados",
            "problemas adicionais",
            "impacto provavel",
            "acao recomendada",
            "limites",
        ],
    },
    "evidencias": {
        "label": "Evidencias",
        "objective": "mostrar o que o NetGuard observou de fato, por que isso sustenta a interpretacao e o que ainda e incerto.",
        "order": [
            "fatos observados",
            "evidencias",
            "inferencia operacional",
            "prioridade",
            "acao recomendada",
            "limites",
        ],
    },
}

MINIMAL_OPERATIONAL_RUNBOOKS = {
    "loop_risk": {
        "title": "Loop L2 / loop_risk",
        "actions": [
            "Isolar uma das portas envolvidas no segmento suspeito.",
            "Validar STP ou RSTP no domínio afetado.",
            "Validar Loop Guard ou proteção equivalente.",
            "Verificar conexão redundante indevida ou fechamento físico de loop.",
            "Confirmar se MAC flapping e broadcast storm cessaram após a contenção.",
            "Tratar flap de interface separado do loop quando ocorrer em outra porta.",
        ],
    },
    "broadcast_storm": {
        "title": "Broadcast storm",
        "actions": [
            "Conter o segmento ou a porta que concentra o storm.",
            "Verificar se há loop L2, flooding anormal ou controle de storm desabilitado.",
            "Confirmar redução do volume de sinais após a contenção.",
        ],
    },
    "mac_flapping": {
        "title": "MAC flapping",
        "actions": [
            "Verificar movimentação anormal de MAC entre portas.",
            "Conferir redundância indevida, agregação incorreta ou loop L2.",
            "Confirmar se o flap de MAC cessa após isolar a porta suspeita.",
        ],
    },
    "interface_flap": {
        "title": "Interface flap",
        "actions": [
            "Verificar porta, cabo, ótico ou negociação na interface afetada.",
            "Conferir logs de up down e traps linkUp linkDown da mesma interface.",
            "Separar causa física ou administrativa do evento de loop se o contexto for distinto.",
        ],
    },
    "snmp_indisponivel": {
        "title": "SNMP indisponível",
        "actions": [
            "Confirmar reachability do host e acesso UDP 161.",
            "Validar community, ACL, firewall ou perfil SNMP aplicado.",
            "Conferir se a indisponibilidade e isolada da coleta ou do host inteiro.",
        ],
    },
    "host_down": {
        "title": "Host down",
        "actions": [
            "Confirmar perda de conectividade do host e do segmento de acesso.",
            "Verificar energia, uplink, ICMP e coleta recente.",
            "Separar indisponibilidade total do host de falha apenas de uma interface ou de SNMP.",
        ],
    },
    "icmp_loss_latency": {
        "title": "Perda ou latência ICMP",
        "actions": [
            "Validar perda, jitter e latência no período recente.",
            "Correlacionar com flap, erros ou descartes de interface.",
            "Confirmar se o impacto é persistente ou transitório antes de escalar.",
        ],
    },
    "syslog_critical": {
        "title": "Syslog crítico",
        "actions": [
            "Ler a mensagem crítica no contexto do host e do incidente.",
            "Correlacionar com sinais de disponibilidade, flap ou loop.",
            "Confirmar se houve repetição ou propagação para outras interfaces ou hosts.",
        ],
    },
}

PRODUCT_AI_CONTEXT = {
    "product_name": "NetGuard",
    "product_summary": (
        "Plataforma de monitoramento orientada por host, com telemetria, eventos, incidentes, "
        "dashboards e apoio contextual por IA no mesmo fluxo."
    ),
    "product_positioning": (
        "Solução de monitoramento e contexto operacional com foco atual em consolidar operação, "
        "interpretação de sinais e rastreabilidade por host. A arquitetura já foi organizada para "
        "crescer por grupos, templates, dashboards e integrações, sem afirmar paridade com suítes enterprise."
    ),
    "current_scope_statement": (
        "Hoje o valor principal do NetGuard está no monitoramento orientado por host: ele reúne SNMP, "
        "syslog, incidentes, previsões, loop_risk, dashboards e IA no mesmo contexto operacional."
    ),
    "article_context": {
        "theme": "monitoramento proativo e rastreabilidade de incidentes em redes corporativas",
        "academic_positioning": (
            "O artigo/TCC deve defender o NetGuard como uma plataforma academica aplicada, com ambicao de produto, "
            "que integra coleta, telemetria, incidentes, alertas, dashboards e apoio por IA para reduzir tempo de diagnostico."
        ),
        "evaluation_metrics": [
            "MTTD: tempo médio entre o início/detecção real de uma falha e o registro do incidente pelo NetGuard.",
            "MTTA: tempo médio até reconhecimento ou primeira ação operacional.",
            "MTTR: tempo médio entre a abertura/detecção do incidente e sua resolução confirmada.",
            "Disponibilidade: percentual de amostras em que o host estava ativo no período analisado.",
            "Taxa de alertas suprimidos: medida de controle de ruído e anti-spam.",
            "Rastreabilidade: capacidade de explicar quais sinais sustentaram cada incidente.",
        ],
        "comparison_guardrail": (
            "Comparacoes com Zabbix e SolarWinds devem ser conceituais e funcionais. "
            "Nao afirmar paridade total nem media melhor sem experimento controlado e dados historicos."
        ),
    },
    "current_capabilities": [
        "Monitoramento operacional por host com drill-down dedicado.",
        "Coleta via SNMP para disponibilidade, sistema e interfaces.",
        "Coleta e leitura de syslog recente no contexto do host.",
        "Fila de incidentes com severidade, status e vínculo com o ativo.",
        "Previsões e anomalias com destaque para loop_risk.",
        "Dashboards Grafana por ambiente, host e grupo.",
        "Cadastro orientado por grupos e templates de monitoramento.",
        "Insights de IA para resumo, explicação, recomendação e chat contextual.",
    ],
    "supported_device_scope_now": [
        "Hosts Linux no template Linux Basic.",
        "Dispositivos de rede SNMP genéricos no template Generic SNMP Switch.",
        "O template NetGuard Lab Device, usado no ambiente controlado do lab-linux-01.",
    ],
    "product_areas": {
        "monitoramento": [
            "Visão geral",
            "Incidentes",
            "Hosts monitorados",
            "Sinais recentes",
            "Drill-down operacional por host",
        ],
        "coleta_de_dados": [
            "Hosts",
            "Grupos de hosts",
            "Templates",
            "Descoberta",
            "Editor de host",
        ],
        "relatorios": [
            "Resumo técnico",
            "Consolidação técnica para análise, comunicação e prestação de contas operacional",
        ],
        "ia_insights": [
            "Resumo do host",
            "Explicação do incidente",
            "Recomendação operacional",
            "Resumo técnico",
            "Assistente contextual do NetGuard",
        ],
    },
    "demo_environment": {
        "main_host": DEMO_HOST_NAME,
        "main_ip": DEMO_HOST_IP,
        "main_template_slug": DEMO_TEMPLATE_SLUG,
        "purpose": "Ativo principal do ambiente de referência controlado, usado para validação funcional e demonstração do fluxo completo do produto.",
    },
    "planned_vendor_targets": [
        "Aruba AOS-CX Basic",
        "Cisco IOS Basic",
        "Dell OS10 Basic",
        "HPE/ProCurve Basic",
    ],
    "current_strengths": [
        "Fluxo operacional guiado por host, sem espalhar a leitura entre muitas telas desconectadas.",
        "Correlação prática entre SNMP, syslog, incidentes, previsões e loop_risk no mesmo contexto.",
        "Dashboards e IA já conectados ao host, ao grupo e ao ambiente monitorado.",
        "Cadastro separado da operação por grupos, templates e editor de host dedicado.",
    ],
    "corporate_value_points": [
        "Melhora a leitura operacional ao reunir sinais e contexto do mesmo ativo em um único fluxo.",
        "Ajuda a rastrear de onde veio um incidente e quais sinais sustentam a interpretação.",
        "Tem base consistente para crescer por grupos, templates e dashboards sem trocar o modelo mental do operador.",
        "Já entrega valor em ambientes corporativos que dependem de observabilidade orientada por host e contexto claro.",
    ],
    "current_limits": [
        "Projeto ainda em evolução, com foco em consolidar operação, templates e experiência de uso.",
        "Cobertura de vendors e templates ainda é menor do que plataformas de mercado mais maduras.",
        "O foco atual está em clareza operacional e extensibilidade, não em paridade total com suítes enterprise.",
    ],
    "roadmap_focus": [
        "Ampliar templates por vendor e família de dispositivo.",
        "Expandir grupos, dashboards e experiência operacional sem aumentar demais a complexidade.",
        "Fortalecer o uso de IA contextual para explicação e apoio técnico.",
    ],
}

app = FastAPI(title="NetGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["*"],
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_conn():
    return psycopg.connect(DATABASE_URL)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def create_access_token(user: dict[str, Any]) -> tuple[str, str]:
    expires_at = utc_now() + timedelta(minutes=AUTH_TOKEN_TTL_MINUTES)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user["id"]),
        "name": user.get("name"),
        "email": user.get("email"),
        "role": user.get("role"),
        "exp": int(expires_at.timestamp()),
        "iat": int(utc_now().timestamp()),
    }
    signing_input = ".".join(
        [
            b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ]
    )
    signature = hmac.new(AUTH_SECRET.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(signature)}", expires_at.isoformat()


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}"
        expected = hmac.new(AUTH_SECRET.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
        received = b64url_decode(signature_b64)
        if not hmac.compare_digest(expected, received):
            raise ValueError("invalid signature")
        payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Sessao invalida. Faca login novamente.") from exc

    exp = int(payload.get("exp") or 0)
    if exp < int(utc_now().timestamp()):
        raise HTTPException(status_code=401, detail="Sessao expirada. Faca login novamente.")
    return payload


def bearer_token_from_request(request: Request) -> Optional[str]:
    auth_header = request.headers.get("authorization") or ""
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    return token or None


def service_token_valid(request: Request) -> bool:
    if not SERVICE_TOKEN:
        return False
    provided = request.headers.get("x-netguard-service-token") or ""
    return hmac.compare_digest(provided, SERVICE_TOKEN)


def user_from_token(token: str) -> dict[str, Any]:
    payload = decode_access_token(token)
    user_id = int(payload.get("sub") or 0)
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, name, email, role, active, must_change_password, last_login_at
            FROM users
            WHERE id=%s
              AND active=true
            LIMIT 1
            """,
            (user_id,),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Usuario inativo ou inexistente.")
    return {
        "id": row[0],
        "name": row[1],
        "email": row[2],
        "role": row[3],
        "active": row[4],
        "must_change_password": row[5],
        "last_login_at": to_iso(row[6]) if "to_iso" in globals() else row[6],
    }


def request_user(request: Request) -> Optional[dict[str, Any]]:
    return getattr(request.state, "user", None)


def require_request_user(request: Request) -> dict[str, Any]:
    user = request_user(request)
    if not user or user.get("type") == "service":
        raise HTTPException(status_code=401, detail="Autenticacao obrigatoria.")
    return user


def audit_action_for_request(method: str, path: str) -> Optional[str]:
    if path == "/auth/logout":
        return None
    if path.startswith("/users"):
        return f"user.{method.lower()}"
    if path.startswith("/discovery"):
        return f"discovery.{method.lower()}"
    if path.startswith("/templates") or path.startswith("/monitoring/items"):
        return f"template.{method.lower()}"
    if path.startswith("/hosts"):
        if "/template" in path or "/profiles" in path or "/interfaces/" in path:
            return f"host.monitoring.{method.lower()}"
        return f"host.{method.lower()}"
    if path.startswith("/alerts/channels"):
        return f"alert_channel.{method.lower()}"
    if path.startswith("/alerts/incidents") or path.startswith("/incidents"):
        return f"incident.{method.lower()}"
    if path.startswith("/ai"):
        return f"ai.{method.lower()}"
    return None


def log_audit_event(
    *,
    actor: Optional[dict[str, Any]],
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_events (
                    actor, actor_user_id, actor_email, actor_role,
                    action, target_type, target_id, details, ip_address, user_agent
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    actor.get("name") if actor else None,
                    actor.get("id") if actor and actor.get("type") != "service" else None,
                    actor.get("email") if actor else None,
                    actor.get("role") if actor else actor.get("type") if actor else None,
                    action,
                    target_type,
                    target_id,
                    psycopg.types.json.Json(details or {}),
                    request.client.host if request and request.client else None,
                    request.headers.get("user-agent") if request else None,
                ),
            )
            conn.commit()
    except Exception:
        # Auditoria nunca deve derrubar o fluxo operacional principal.
        return


def is_public_path(method: str, path: str) -> bool:
    if method == "OPTIONS":
        return True
    exact = {
        "/health",
        "/health/deep",
        "/auth/login",
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
    }
    return path in exact


def service_roles_allowed(method: str, path: str) -> bool:
    if method != "POST":
        return False
    if path == "/alerts":
        return True
    if path == "/ai/chat":
        return True
    if path == "/lab/bootstrap":
        return True
    if re.match(r"^/alerts/incidents/\d+/(notify|resolve)$", path):
        return True
    return False


def required_roles_for_request(method: str, path: str) -> set[str]:
    any_authenticated = {"admin", "operator", "viewer", "auditor"}
    operator_plus = {"admin", "operator"}
    admin_only = {"admin"}

    if path in {"/auth/me", "/auth/logout", "/auth/change-password"}:
        return any_authenticated
    if path.startswith("/users") or path.startswith("/audit-logs"):
        return admin_only
    if path.startswith("/discovery"):
        return admin_only
    if path.startswith("/templates"):
        return any_authenticated if method == "GET" else admin_only
    if path.startswith("/monitoring/items"):
        return admin_only
    if re.match(r"^/hosts/\d+/template$", path):
        return admin_only
    if path.startswith("/host-groups"):
        return any_authenticated if method == "GET" else admin_only
    if path.startswith("/alerts/channels"):
        if method == "GET":
            return any_authenticated
        if path.endswith("/test"):
            return operator_plus
        return admin_only
    if path in {"/alerts/test"}:
        return operator_plus
    if path.startswith("/alerts/incidents") and method == "POST":
        return operator_plus
    if re.match(r"^/incidents/\d+/resolve$", path):
        return operator_plus
    if path.startswith("/hosts"):
        if method == "GET":
            return any_authenticated
        if path.endswith("/collect-now") or path.endswith("/discover-interfaces"):
            return operator_plus
        return admin_only
    if path.startswith("/ai"):
        return operator_plus
    if method != "GET":
        return admin_only
    return any_authenticated


@app.middleware("http")
async def netguard_auth_middleware(request: Request, call_next):
    method = request.method.upper()
    path = request.url.path

    if not AUTH_ENABLED or is_public_path(method, path):
        response = await call_next(request)
        return response

    actor = None
    if service_roles_allowed(method, path) and service_token_valid(request):
        actor = {"type": "service", "name": "netguard-service", "role": "service", "email": "service@netguard.local"}
        request.state.user = actor
    else:
        token = bearer_token_from_request(request)
        if not token:
            return JSONResponse(status_code=401, content={"detail": "Autenticacao obrigatoria."})
        try:
            actor = user_from_token(token)
            request.state.user = actor
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

        if actor.get("must_change_password") and path not in {"/auth/me", "/auth/logout", "/auth/change-password"}:
            return JSONResponse(
                status_code=403,
                content={"detail": "Altere sua senha antes de continuar."},
            )

        allowed_roles = required_roles_for_request(method, path)
        if actor.get("role") not in allowed_roles:
            return JSONResponse(
                status_code=403,
                content={"detail": "Voce nao tem permissao para executar esta acao."},
            )

    response = await call_next(request)
    action = audit_action_for_request(method, path)
    if action and response.status_code < 400 and method != "GET":
        log_audit_event(
            actor=actor,
            action=action,
            target_type=path.strip("/").split("/", 1)[0] or "api",
            details={"method": method, "path": path, "status_code": response.status_code},
            request=request,
        )
    return response


@app.on_event("startup")
def ensure_auth_bootstrap() -> None:
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    last_login_at TIMESTAMPTZ
                )
                """
            )
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT TRUE")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (LOWER(email))")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id BIGSERIAL PRIMARY KEY,
                    actor TEXT,
                    actor_user_id INTEGER,
                    actor_email TEXT,
                    actor_role TEXT,
                    action TEXT NOT NULL,
                    target_type TEXT,
                    target_id TEXT,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_user_id INTEGER")
            cur.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_email TEXT")
            cur.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_role TEXT")
            cur.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS ip_address TEXT")
            cur.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS user_agent TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_events_created ON audit_events (created_at DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_events_actor_created ON audit_events (actor_user_id, created_at DESC)")
            cur.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=true")
            has_admin = int(cur.fetchone()[0] or 0) > 0
            if not has_admin:
                cur.execute(
                    """
                    INSERT INTO users (name, email, password, role, active, must_change_password)
                    VALUES ('Admin', 'admin@netguard.local', %s, 'admin', true, true)
                    ON CONFLICT (email) DO NOTHING
                    """,
                    (hash_password(DEFAULT_USER_PASSWORD),),
                )
                cur.execute(
                    """
                    INSERT INTO audit_events (actor, actor_email, actor_role, action, target_type, details)
                    VALUES ('system', 'system@netguard.local', 'system', 'auth.bootstrap_admin', 'users', %s)
                    """,
                    (psycopg.types.json.Json({"email": "admin@netguard.local", "must_change_password": True}),),
                )
            conn.commit()
    except Exception:
        return


def build_alert_service(cur) -> AlertService:
    return AlertService(
        PostgresIncidentRepository(cur, assets_table=ASSETS_TABLE),
        load_alert_config(),
    )


def has_host_groups_schema(cur) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'host_groups'
        )
        """
    )
    groups_table_exists = bool(cur.fetchone()[0])

    if not groups_table_exists:
        return False

    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'host_groups'
        """
    )
    group_columns = {row[0] for row in cur.fetchall()}

    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = %s
        """,
        (ASSETS_TABLE,),
    )
    asset_columns = {row[0] for row in cur.fetchall()}

    required_group_columns = {"id", "name", "slug", "parent_id", "path", "tags", "enabled"}
    return required_group_columns.issubset(group_columns) and "group_id" in asset_columns


def has_monitoring_templates_schema(cur) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'monitoring_templates'
        )
        """
    )
    templates_table_exists = bool(cur.fetchone()[0])

    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'template_profiles'
        )
        """
    )
    template_profiles_exists = bool(cur.fetchone()[0])

    if not templates_table_exists or not template_profiles_exists:
        return False

    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'monitoring_templates'
        """
    )
    template_columns = {row[0] for row in cur.fetchall()}

    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = %s
        """,
        (ASSETS_TABLE,),
    )
    asset_columns = {row[0] for row in cur.fetchall()}

    required_template_columns = {
        "id",
        "name",
        "slug",
        "asset_type",
        "vendor",
        "family",
        "summary",
        "definition",
        "preview",
        "enabled",
    }
    return required_template_columns.issubset(template_columns) and "template_id" in asset_columns


def has_ai_insights_schema(cur) -> bool:
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'ai_insights'
        """
    )
    columns = {row[0] for row in cur.fetchall()}
    required = {
        "id",
        "target_type",
        "target_id",
        "insight_type",
        "status",
        "model",
        "content_md",
        "content_json",
        "evidence_json",
        "created_at",
        "expires_at",
    }
    return required.issubset(columns)


def host_group_row_to_dict(row) -> dict[str, Any]:
    return {
        "id": row[0],
        "name": row[1],
        "slug": row[2],
        "parent_id": row[3],
        "path": row[4],
        "tags": row[5] or {},
        "enabled": bool(row[6]),
    }


def list_host_group_rows(cur):
    cur.execute(
        """
        SELECT id, name, slug, parent_id, path, tags, enabled
        FROM host_groups
        ORDER BY path, id
        """
    )
    return cur.fetchall()


def get_host_group_record(cur, group_id: int) -> dict[str, Any]:
    cur.execute(
        """
        SELECT id, name, slug, parent_id, path, tags, enabled
        FROM host_groups
        WHERE id = %s
        """,
        (group_id,),
    )
    row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Grupo de hosts não encontrado.")

    return host_group_row_to_dict(row)


def slugify_group_name(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return slug or "group"


def build_host_group_slug_and_path(
    cur,
    name: str,
    parent_id: Optional[int] = None,
    exclude_id: Optional[int] = None,
) -> tuple[str, str]:
    parent_path = None

    if parent_id is not None:
        parent = get_host_group_record(cur, parent_id)
        parent_path = parent["path"]

    base_slug = slugify_group_name(name)
    attempt = 1

    while True:
        slug = base_slug if attempt == 1 else f"{base_slug}-{attempt}"
        path = slug if parent_path is None else f"{parent_path}/{slug}"

        query = "SELECT 1 FROM host_groups WHERE LOWER(path) = LOWER(%s)"
        params: list[Any] = [path]

        if exclude_id is not None:
            query += " AND id <> %s"
            params.append(exclude_id)

        cur.execute(query, params)
        if cur.fetchone() is None:
            return slug, path

        attempt += 1


def update_host_group_descendant_paths(cur, old_path: str, new_path: str):
    if old_path == new_path:
        return

    cur.execute(
        """
        SELECT id, path
        FROM host_groups
        WHERE path LIKE %s
        ORDER BY LENGTH(path), path
        """,
        (f"{old_path}/%",),
    )
    descendants = cur.fetchall()

    for group_id, descendant_path in descendants:
        suffix = descendant_path[len(old_path):]
        cur.execute(
            "UPDATE host_groups SET path = %s WHERE id = %s",
            (f"{new_path}{suffix}", group_id),
        )


def ensure_lab_group(cur) -> Optional[int]:
    if not has_host_groups_schema(cur):
        return None

    cur.execute(
        """
        SELECT id
        FROM host_groups
        WHERE LOWER(path) = 'lab'
           OR LOWER(name) = 'lab'
        ORDER BY id
        LIMIT 1
        """
    )
    row = cur.fetchone()

    if row is not None:
        return row[0]

    cur.execute(
        """
        INSERT INTO host_groups (name, slug, parent_id, path, tags, enabled)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            "Lab",
            "lab",
            None,
            "lab",
            psycopg.types.json.Json({"system": True, "lab": True}),
            True,
        ),
    )
    return cur.fetchone()[0]


def normalize_group_id(cur, group_id: Optional[int]) -> Optional[int]:
    if group_id is None:
        return None

    if not has_host_groups_schema(cur):
        raise HTTPException(status_code=503, detail="O schema de grupos de hosts ainda não foi inicializado.")

    get_host_group_record(cur, group_id)
    return group_id


def build_host_groups_tree(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    nodes = {
        group["id"]: {
            **group,
            "children": [],
        }
        for group in groups
    }
    roots: list[dict[str, Any]] = []

    for group in groups:
        node = nodes[group["id"]]
        parent_id = group["parent_id"]

        if parent_id is not None and parent_id in nodes:
            nodes[parent_id]["children"].append(node)
        else:
            roots.append(node)

    return roots


def has_assets_collection_policy_schema(cur) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = %s
              AND column_name = 'collection_policy_override'
        )
        """,
        (ASSETS_TABLE,),
    )
    return bool(cur.fetchone()[0])


def has_collection_requests_schema(cur) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'collection_requests'
        )
        """
    )
    return bool(cur.fetchone()[0])


def has_table(cur, table_name: str) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = %s
        )
        """,
        (table_name,),
    )
    return bool(cur.fetchone()[0])


def has_table_columns(cur, table_name: str, required_columns: set[str]) -> bool:
    if not has_table(cur, table_name):
        return False
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = %s
        """,
        (table_name,),
    )
    return required_columns.issubset({row[0] for row in cur.fetchall()})


def has_monitoring_items_schema(cur) -> bool:
    return has_table_columns(
        cur,
        "monitoring_items",
        {
            "id",
            "host_id",
            "template_id",
            "protocol",
            "item_key",
            "display_name",
            "enabled",
            "poll_interval_seconds",
            "timeout_seconds",
            "retries",
            "history_retention_days",
            "trend_retention_days",
            "log_retention_days",
        },
    )


def has_network_discovery_schema(cur) -> bool:
    return has_table(cur, "network_discovery_runs") and has_table(cur, "network_discovery_results")


def has_syslog_correlation_schema(cur) -> bool:
    return has_table(cur, "syslog_interface_correlations")


COLLECTION_POLICY_FIELDS = (
    "icmp_interval_sec",
    "snmp_interval_sec",
    "tcp_interval_sec",
    "timeout_sec",
    "retries",
    "history_retention_days",
    "trend_retention_days",
    "log_retention_days",
    "incident_retention_days",
    "notification_retention_days",
    "audit_retention_days",
)

COLLECTION_POLICY_LIMITS = {
    "icmp_interval_sec": (5, 3600),
    "snmp_interval_sec": (5, 3600),
    "tcp_interval_sec": (5, 3600),
    "timeout_sec": (1, 30),
    "retries": (0, 10),
    "history_retention_days": (1, 3650),
    "trend_retention_days": (1, 3650),
    "log_retention_days": (1, 3650),
    "incident_retention_days": (1, 3650),
    "notification_retention_days": (1, 3650),
    "audit_retention_days": (1, 3650),
}

COLLECTION_POLICY_SOURCE_LABELS = {
    "global": "Fallback global",
    "template": "Template",
    "host_override": "Override do host",
}


def default_collection_policy() -> dict[str, int]:
    return {
        "icmp_interval_sec": DEFAULT_ICMP_INTERVAL_SEC,
        "snmp_interval_sec": DEFAULT_SNMP_INTERVAL_SEC,
        "tcp_interval_sec": 60,
        "timeout_sec": DEFAULT_COLLECTION_TIMEOUT_SEC,
        "retries": DEFAULT_COLLECTION_RETRIES,
        "history_retention_days": 30,
        "trend_retention_days": 90,
        "log_retention_days": 14,
        "incident_retention_days": 180,
        "notification_retention_days": 90,
        "audit_retention_days": 365,
    }


def normalize_collection_policy(raw: Any) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}

    normalized: dict[str, int] = {}

    for field in COLLECTION_POLICY_FIELDS:
        value = raw.get(field)
        if value in (None, ""):
            continue

        try:
            numeric = int(float(value))
        except (TypeError, ValueError):
            continue

        minimum, maximum = COLLECTION_POLICY_LIMITS[field]
        numeric = max(minimum, min(maximum, numeric))
        normalized[field] = numeric

    return normalized


def extract_template_collection_policy(definition: Any) -> dict[str, int]:
    if not isinstance(definition, dict):
        return {}
    return normalize_collection_policy(definition.get("collection_policy") or {})


def resolve_collection_policy(
    *,
    template_definition: Any = None,
    host_override: Any = None,
) -> tuple[dict[str, int], dict[str, str], str]:
    resolved = default_collection_policy()
    sources = {field: "global" for field in COLLECTION_POLICY_FIELDS}

    template_policy = extract_template_collection_policy(template_definition)
    for field, value in template_policy.items():
        resolved[field] = value
        sources[field] = "template"

    override_policy = normalize_collection_policy(host_override or {})
    for field, value in override_policy.items():
        resolved[field] = value
        sources[field] = "host_override"

    if override_policy:
        source = "host_override"
    elif template_policy:
        source = "template"
    else:
        source = "global"

    return resolved, sources, source


def merge_collection_policy_into_definition(definition: Any, policy: dict[str, int]) -> dict[str, Any]:
    base = dict(definition) if isinstance(definition, dict) else {}
    base["collection_policy"] = normalize_collection_policy(policy)
    return base


def collection_policy_source_labels(sources: dict[str, str]) -> dict[str, str]:
    return {
        field: COLLECTION_POLICY_SOURCE_LABELS.get(source, source)
        for field, source in (sources or {}).items()
    }


def add_seconds_to_iso(value: Optional[str], seconds: Optional[int]) -> Optional[str]:
    if not value or not seconds:
        return None

    parsed = parse_datetime_filter(value)
    if parsed is None:
        return None

    return to_iso(parsed + timedelta(seconds=int(seconds)))


def ip_without_cidr(value: Any) -> str:
    return str(value or "").strip().split("/", 1)[0]


def collection_policy_summary(policy: Optional[dict[str, Any]]) -> str:
    normalized = normalize_collection_policy(policy or {})
    if not normalized:
        return "Fallback global"

    return (
        f"ICMP {normalized['icmp_interval_sec']}s | "
        f"SNMP {normalized['snmp_interval_sec']}s | "
        f"timeout {normalized['timeout_sec']}s | "
        f"retries {normalized['retries']} | "
        f"history {normalized['history_retention_days']}d | "
        f"trends {normalized['trend_retention_days']}d | "
        f"logs {normalized['log_retention_days']}d | "
        f"incidents {normalized['incident_retention_days']}d | "
        f"notifications {normalized['notification_retention_days']}d | "
        f"audit {normalized['audit_retention_days']}d"
    )



HOST_BASE_SELECT_PARTS = [
    "a.id",
    "a.name",
    "a.ip",
    "a.snmp_profile",
    "a.tags",
    "a.enabled",
]

HOST_COLLECTION_POLICY_SELECT_PARTS = ["a.collection_policy_override"]

HOST_GROUP_SELECT_PARTS = ["a.group_id", "g.name", "g.path"]

HOST_TEMPLATE_SELECT_PARTS = [
    "a.template_id",
    "t.name",
    "t.slug",
    "t.asset_type",
    "t.vendor",
    "t.family",
    "t.summary",
    "t.definition",
]

MONITORING_TEMPLATE_SELECT = """
    SELECT
        id,
        name,
        slug,
        asset_type,
        vendor,
        family,
        summary,
        definition,
        preview,
        enabled
    FROM monitoring_templates
"""


def build_host_select_parts(
    groups_ready: bool,
    templates_ready: bool,
    collection_policy_ready: bool,
) -> list[str]:
    select_parts = list(HOST_BASE_SELECT_PARTS)

    if collection_policy_ready:
        select_parts.extend(HOST_COLLECTION_POLICY_SELECT_PARTS)

    if groups_ready:
        select_parts.extend(HOST_GROUP_SELECT_PARTS)

    if templates_ready:
        select_parts.extend(HOST_TEMPLATE_SELECT_PARTS)

    return select_parts


def host_row_to_dict(
    row,
    groups_ready: bool,
    templates_ready: bool,
    collection_policy_ready: bool,
) -> dict[str, Any]:
    def safe_mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def safe_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    offset = len(HOST_BASE_SELECT_PARTS)
    snmp_profile = safe_mapping(row[3])
    tags = safe_mapping(row[4])
    host = {
        "id": row[0],
        "name": row[1] or f"host-{ip_without_cidr(row[2])}",
        "ip": ip_without_cidr(row[2]),
        "snmp_profile": snmp_profile,
        "tags": tags,
        "enabled": bool(row[5]),
        "collection_policy_override": {},
        "group_id": None,
        "group_name": None,
        "group_path": None,
        "template_id": None,
        "template_name": None,
        "template_slug": None,
        "template_asset_type": None,
        "template_vendor": None,
        "template_family": None,
        "template_summary": None,
        "collection_policy_resolved": default_collection_policy(),
        "collection_policy_sources": {
            field: "global" for field in COLLECTION_POLICY_FIELDS
        },
        "collection_policy_source": "global",
        "collection_policy_source_labels": {
            field: COLLECTION_POLICY_SOURCE_LABELS["global"] for field in COLLECTION_POLICY_FIELDS
        },
        "discovery_source": safe_text(tags.get("discovery_source") or tags.get("source") or tags.get("group")),
        "_template_definition": {},
    }

    if collection_policy_ready:
        host["collection_policy_override"] = normalize_collection_policy(row[offset] or {})
        offset += 1

    if groups_ready:
        host["group_id"] = row[offset]
        host["group_name"] = safe_text(row[offset + 1]) or host["group_name"]
        host["group_path"] = safe_text(row[offset + 2]) or host["group_path"]
        offset += 3

    if templates_ready:
        host["template_id"] = row[offset]
        host["template_name"] = safe_text(row[offset + 1])
        host["template_slug"] = safe_text(row[offset + 2])
        host["template_asset_type"] = safe_text(row[offset + 3])
        host["template_vendor"] = safe_text(row[offset + 4])
        host["template_family"] = safe_text(row[offset + 5])
        host["template_summary"] = safe_text(row[offset + 6])
        host["_template_definition"] = row[offset + 7] if isinstance(row[offset + 7], dict) else {}

    if host["group_id"] is None and host["discovery_source"] in {"network_discovery", "discovery"}:
        host["group_name"] = host["group_name"] or "Discovery"
        host["group_path"] = host["group_path"] or "discovery"

    if host["template_id"] is None:
        host["template_slug"] = host["template_slug"] or safe_text(tags.get("suggested_template_slug"))
        host["template_name"] = host["template_name"] or safe_text(tags.get("suggested_template_name"))

    if host["template_name"] is None and host["discovery_source"] in {"network_discovery", "discovery"}:
        fallback_template = discovery_template_fallback(
            {
                "snmp_status": "up" if bool(snmp_profile.get("enabled")) else "down",
                "suggested_template_slug": tags.get("suggested_template_slug"),
                "suggested_template_name": tags.get("suggested_template_name"),
            }
        )
        host["template_slug"] = host["template_slug"] or fallback_template["template_slug"]
        host["template_name"] = host["template_name"] or fallback_template["template_name"]

    resolved_policy, policy_sources, policy_source = resolve_collection_policy(
        template_definition=host.get("_template_definition"),
        host_override=host.get("collection_policy_override"),
    )
    host["collection_policy_resolved"] = resolved_policy
    host["collection_policy_sources"] = policy_sources
    host["collection_policy_source"] = policy_source
    host["collection_policy_source_labels"] = collection_policy_source_labels(policy_sources)

    return host


def host_api_payload(host: dict[str, Any]) -> dict[str, Any]:
    payload = dict(host or {})
    payload["name"] = str(payload.get("name") or f"host-{ip_without_cidr(payload.get('ip') or 'unknown')}").strip()
    payload["ip"] = ip_without_cidr(payload.get("ip") or "0.0.0.0")
    payload["snmp_profile"] = payload.get("snmp_profile") if isinstance(payload.get("snmp_profile"), dict) else {}
    payload["tags"] = payload.get("tags") if isinstance(payload.get("tags"), dict) else {}
    payload["collection_policy_override"] = (
        payload.get("collection_policy_override") if isinstance(payload.get("collection_policy_override"), dict) else {}
    )
    payload["collection_policy_resolved"] = (
        payload.get("collection_policy_resolved")
        if isinstance(payload.get("collection_policy_resolved"), dict)
        else default_collection_policy()
    )
    payload["collection_policy_sources"] = (
        payload.get("collection_policy_sources") if isinstance(payload.get("collection_policy_sources"), dict) else {}
    )
    payload["collection_policy_source_labels"] = (
        payload.get("collection_policy_source_labels")
        if isinstance(payload.get("collection_policy_source_labels"), dict)
        else {}
    )
    payload["enabled"] = bool(payload.get("enabled"))
    payload["discovery_source"] = str(
        payload.get("discovery_source")
        or payload["tags"].get("discovery_source")
        or payload["tags"].get("source")
        or ""
    ).strip() or None

    if not payload.get("group_name") and payload["discovery_source"] in {"network_discovery", "discovery"}:
        payload["group_name"] = "Discovery"
    if not payload.get("group_path") and payload["discovery_source"] in {"network_discovery", "discovery"}:
        payload["group_path"] = "discovery"

    if not payload.get("template_name"):
        fallback_template = discovery_template_fallback(
            {
                "snmp_status": "up" if bool(payload["snmp_profile"].get("enabled")) else "down",
                "suggested_template_slug": payload["tags"].get("suggested_template_slug"),
                "suggested_template_name": payload["tags"].get("suggested_template_name"),
            }
        )
        payload["template_slug"] = payload.get("template_slug") or fallback_template["template_slug"]
        payload["template_name"] = payload.get("template_name") or fallback_template["template_name"]

    return payload


def template_profile_row_to_dict(row) -> dict[str, Any]:
    return {
        "profile_id": row[0],
        "name": row[1],
        "display_name": row[2] or row[1],
        "kind": row[3],
        "description": row[4],
        "config": row[5] or {},
        "params": row[6] or {},
        "enabled": bool(row[7]),
        "sort_order": int(row[8] or 0),
    }


def list_template_profile_rows(cur, template_id: int):
    cur.execute(
        """
        SELECT
            mp.id,
            mp.name,
            mp.display_name,
            mp.kind,
            mp.description,
            mp.config,
            tp.params,
            tp.enabled,
            tp.sort_order
        FROM template_profiles tp
        JOIN monitoring_profiles mp ON mp.id = tp.profile_id
        WHERE tp.template_id = %s
        ORDER BY tp.sort_order, mp.display_name, mp.name
        """,
        (template_id,),
    )
    return cur.fetchall()


def list_template_profile_records(cur, template_id: int) -> list[dict[str, Any]]:
    return [
        template_profile_row_to_dict(profile_row)
        for profile_row in list_template_profile_rows(cur, template_id)
    ]


def monitoring_template_row_to_dict(row) -> dict[str, Any]:
    definition = row[7] or {}
    capabilities = definition.get("capabilities", {}) if isinstance(definition, dict) else {}
    collection_policy = extract_template_collection_policy(definition)

    return {
        "id": row[0],
        "name": row[1],
        "slug": row[2],
        "asset_type": row[3],
        "vendor": row[4],
        "family": row[5],
        "summary": row[6],
        "definition": definition,
        "capabilities": capabilities if isinstance(capabilities, dict) else {},
        "preview": row[8] or {},
        "enabled": bool(row[9]),
        "collection_policy": collection_policy or default_collection_policy(),
    }


def hydrate_monitoring_template(cur, row) -> dict[str, Any]:
    template = monitoring_template_row_to_dict(row)
    template["profiles"] = list_template_profile_records(cur, template["id"])
    return template


def get_monitoring_template_record(cur, template_id: int) -> dict[str, Any]:
    cur.execute(f"{MONITORING_TEMPLATE_SELECT} WHERE id = %s", (template_id,))
    row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Template não encontrado.")

    return hydrate_monitoring_template(cur, row)


def list_monitoring_template_records(cur) -> list[dict[str, Any]]:
    cur.execute(f"{MONITORING_TEMPLATE_SELECT} ORDER BY enabled DESC, name")
    rows = cur.fetchall()

    return [hydrate_monitoring_template(cur, row) for row in rows]


def normalize_template_id(cur, template_id: Optional[int]) -> Optional[int]:
    if template_id is None:
        return None

    if not has_monitoring_templates_schema(cur):
        raise HTTPException(status_code=503, detail="O schema de templates ainda não foi inicializado.")

    template = get_monitoring_template_record(cur, template_id)
    if not template["enabled"]:
        raise HTTPException(status_code=400, detail="O template selecionado não está disponível para associação ao host.")

    return template_id


def get_template_id_by_slug(cur, slug: str) -> Optional[int]:
    if not has_monitoring_templates_schema(cur):
        return None

    cur.execute(
        """
        SELECT id
        FROM monitoring_templates
        WHERE slug = %s
        LIMIT 1
        """,
        (slug,),
    )
    row = cur.fetchone()
    return row[0] if row is not None else None


def update_template_collection_policy(cur, template_id: int, payload: "CollectionPolicyIn") -> dict[str, Any]:
    template = get_monitoring_template_record(cur, template_id)
    normalized_policy = normalize_collection_policy(payload.model_dump(exclude_none=True))
    if not normalized_policy:
        normalized_policy = default_collection_policy()
    next_definition = merge_collection_policy_into_definition(template.get("definition"), normalized_policy)

    cur.execute(
        """
        UPDATE monitoring_templates
        SET definition = %s
        WHERE id = %s
        """,
        (psycopg.types.json.Json(next_definition), template_id),
    )

    return get_monitoring_template_record(cur, template_id)


MONITORING_ITEM_SELECT = """
    id,
    host_id,
    template_id,
    protocol,
    item_key,
    display_name,
    oid,
    unit,
    enabled,
    poll_interval_seconds,
    timeout_seconds,
    retries,
    history_retention_days,
    trend_retention_days,
    log_retention_days,
    last_collected_at,
    last_error,
    config
"""


def monitoring_item_row_to_dict(row, source: str = "template") -> dict[str, Any]:
    return {
        "id": row[0],
        "host_id": row[1],
        "template_id": row[2],
        "source": source,
        "protocol": row[3],
        "item_key": row[4],
        "display_name": row[5],
        "oid": row[6],
        "unit": row[7],
        "enabled": bool(row[8]),
        "poll_interval_seconds": int(row[9] or 30),
        "timeout_seconds": int(row[10] or 1),
        "retries": int(row[11] or 0),
        "history_retention_days": int(row[12] or 30),
        "trend_retention_days": int(row[13] or 90),
        "log_retention_days": int(row[14] or 14),
        "last_collected_at": to_iso(row[15]),
        "last_error": row[16],
        "config": row[17] or {},
    }


def list_template_monitoring_items(cur, template_id: int) -> list[dict[str, Any]]:
    if not has_monitoring_items_schema(cur):
        return []
    cur.execute(
        f"""
        SELECT {MONITORING_ITEM_SELECT}
        FROM monitoring_items
        WHERE template_id = %s
          AND host_id IS NULL
        ORDER BY protocol, item_key
        """,
        (template_id,),
    )
    return [monitoring_item_row_to_dict(row, "template") for row in cur.fetchall()]


def copy_template_items_to_host(cur, host_id: int, template_id: Optional[int]) -> None:
    if not template_id or not has_monitoring_items_schema(cur):
        return
    cur.execute(
        """
        INSERT INTO monitoring_items (
            host_id, protocol, item_key, display_name, oid, unit, enabled,
            poll_interval_seconds, timeout_seconds, retries,
            history_retention_days, trend_retention_days, log_retention_days, config
        )
        SELECT
            %s, protocol, item_key, display_name, oid, unit, enabled,
            poll_interval_seconds, timeout_seconds, retries,
            history_retention_days, trend_retention_days, log_retention_days, config
        FROM monitoring_items
        WHERE template_id = %s
          AND host_id IS NULL
        ON CONFLICT DO NOTHING
        """,
        (host_id, template_id),
    )


def list_host_monitoring_items(cur, host_id: int) -> list[dict[str, Any]]:
    if not has_monitoring_items_schema(cur):
        return []
    host = get_host_record(cur, host_id)
    template_id = host.get("template_id")
    copy_template_items_to_host(cur, host_id, template_id)
    cur.execute(
        f"""
        SELECT {MONITORING_ITEM_SELECT}
        FROM monitoring_items
        WHERE host_id = %s
        ORDER BY protocol, item_key
        """,
        (host_id,),
    )
    host_rows = cur.fetchall()
    if host_rows:
        return [monitoring_item_row_to_dict(row, "host") for row in host_rows]
    if template_id:
        return list_template_monitoring_items(cur, int(template_id))
    return []


def normalize_monitoring_item_update(payload: "MonitoringItemIn") -> dict[str, Any]:
    data = payload.model_dump(exclude_unset=True)
    normalized: dict[str, Any] = {}
    text_fields = {"display_name", "oid", "unit", "last_error"}
    numeric_fields = {
        "poll_interval_seconds": (5, 3600),
        "timeout_seconds": (1, 30),
        "retries": (0, 10),
        "history_retention_days": (1, 3650),
        "trend_retention_days": (1, 3650),
        "log_retention_days": (1, 3650),
    }
    for field, value in data.items():
        if field in text_fields:
            normalized[field] = str(value).strip() if value not in (None, "") else None
        elif field == "enabled":
            normalized[field] = bool(value)
        elif field in numeric_fields and value is not None:
            minimum, maximum = numeric_fields[field]
            normalized[field] = max(minimum, min(maximum, int(float(value))))
        elif field == "config" and isinstance(value, dict):
            normalized[field] = value
    return normalized


def update_monitoring_item(cur, item_id: int, payload: "MonitoringItemIn") -> dict[str, Any]:
    if not has_monitoring_items_schema(cur):
        raise HTTPException(status_code=503, detail="O schema de itens de monitoramento ainda não foi inicializado.")
    normalized = normalize_monitoring_item_update(payload)
    if not normalized:
        cur.execute(f"SELECT {MONITORING_ITEM_SELECT} FROM monitoring_items WHERE id=%s", (item_id,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Item de monitoramento não encontrado.")
        return monitoring_item_row_to_dict(row, "host" if row[1] else "template")

    assignments = []
    values: list[Any] = []
    for field, value in normalized.items():
        assignments.append(f"{field}=%s")
        values.append(psycopg.types.json.Json(value) if field == "config" else value)
    assignments.append("updated_at=now()")
    values.append(item_id)
    cur.execute(
        f"""
        UPDATE monitoring_items
        SET {', '.join(assignments)}
        WHERE id=%s
        RETURNING {MONITORING_ITEM_SELECT}
        """,
        values,
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Item de monitoramento não encontrado.")
    return monitoring_item_row_to_dict(row, "host" if row[1] else "template")


def apply_template_to_host(cur, host_id: int, payload: "ApplyTemplateIn") -> dict[str, Any]:
    template_id = normalize_template_id(cur, payload.template_id)
    cur.execute(f"SELECT 1 FROM {ASSETS_TABLE} WHERE id=%s", (host_id,))
    if cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="Host não encontrado.")
    cur.execute(f"UPDATE {ASSETS_TABLE} SET template_id=%s WHERE id=%s", (template_id, host_id))

    if payload.replace_profiles and has_monitoring_templates_schema(cur):
        cur.execute("DELETE FROM asset_profiles WHERE asset_id=%s", (host_id,))
        cur.execute(
            """
            INSERT INTO asset_profiles (asset_id, profile_id, params, enabled)
            SELECT %s, profile_id, COALESCE(params, '{}'::jsonb), enabled
            FROM template_profiles
            WHERE template_id=%s
            ON CONFLICT DO NOTHING
            """,
            (host_id, template_id),
        )

    if payload.copy_items_to_host:
        cur.execute("DELETE FROM monitoring_items WHERE host_id=%s", (host_id,))
        copy_template_items_to_host(cur, host_id, template_id)

    return get_host_record(cur, host_id)


SNMP_DISCOVERY_OIDS = {
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_uptime": "1.3.6.1.2.1.1.3.0",
}


def mask_secret(value: Optional[str]) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 2:
        return "*" * len(text)
    return f"{text[:1]}***{text[-1:]}"


def classify_discovered_device(sys_descr: Optional[str], sys_object_id: Optional[str], snmp_ok: bool) -> dict[str, str]:
    text = f"{sys_descr or ''} {sys_object_id or ''}".lower()
    if snmp_ok and "catalyst" in text and "2960" in text:
        return {"vendor": "Cisco", "template_slug": "cisco-catalyst-2960"}
    if snmp_ok and ("cisco" in text or "ios" in text):
        return {"vendor": "Cisco", "template_slug": "cisco-ios-switch"}
    if snmp_ok and ("aruba" in text or "aos-cx" in text):
        return {"vendor": "Aruba", "template_slug": "aruba-aos-cx"}
    if snmp_ok and ("hewlett" in text or "procurve" in text or "hpe" in text):
        return {"vendor": "HPE", "template_slug": "aruba-hpe-switch"}
    if snmp_ok and "dell" in text:
        return {"vendor": "Dell", "template_slug": "dell-switch"}
    if snmp_ok:
        return {"vendor": "Desconhecido", "template_slug": "generic-snmp-switch"}
    return {"vendor": "ICMP-only", "template_slug": "icmp-only"}


def ping_host(ip: str, timeout_seconds: int, retries: int) -> bool:
    attempts = max(1, retries + 1)
    for _ in range(attempts):
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, timeout_seconds)), ip],
            text=True,
            capture_output=True,
            timeout=max(2, timeout_seconds + 2),
        )
        if result.returncode == 0:
            return True
    return False


def snmpget_v2c(ip: str, community: str, oid: str, timeout_seconds: int, retries: int) -> Optional[str]:
    result = subprocess.run(
        [
            "snmpget",
            "-v2c",
            "-c",
            community,
            "-t",
            str(max(1, timeout_seconds)),
            "-r",
            str(max(0, retries)),
            "-Oqv",
            ip,
            oid,
        ],
        text=True,
        capture_output=True,
        timeout=max(3, (timeout_seconds * (retries + 1)) + 2),
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value or "No Such" in value:
        return None
    return value


def scan_discovery_ip(ip: str, payload: "NetworkDiscoveryScanIn") -> dict[str, Any]:
    icmp_up = False
    snmp_values: dict[str, Optional[str]] = {}
    snmp_ok = False

    if payload.use_icmp:
        try:
            icmp_up = ping_host(ip, payload.timeout_seconds, payload.retries)
        except Exception:
            icmp_up = False

    if payload.use_snmp and (icmp_up or not payload.use_icmp):
        for key, oid in SNMP_DISCOVERY_OIDS.items():
            try:
                snmp_values[key] = snmpget_v2c(ip, payload.snmp_community, oid, payload.timeout_seconds, payload.retries)
            except Exception:
                snmp_values[key] = None
        snmp_ok = any(snmp_values.values())

    classification = classify_discovered_device(snmp_values.get("sys_descr"), snmp_values.get("sys_object_id"), snmp_ok)
    return {
        "ip": ip,
        "icmp_status": "up" if icmp_up else ("down" if payload.use_icmp else "not_tested"),
        "snmp_status": "up" if snmp_ok else ("down" if payload.use_snmp else "not_tested"),
        "sys_name": snmp_values.get("sys_name"),
        "sys_descr": snmp_values.get("sys_descr"),
        "sys_object_id": snmp_values.get("sys_object_id"),
        "sys_uptime": snmp_values.get("sys_uptime"),
        "detected_vendor": classification["vendor"],
        "suggested_template_slug": classification["template_slug"],
        "raw": {"snmp_checked": bool(payload.use_snmp), "icmp_checked": bool(payload.use_icmp)},
    }


def discovery_result_row_to_dict(row) -> dict[str, Any]:
    return {
        "id": row[0],
        "run_id": row[1],
        "ip": str(row[2]),
        "icmp_status": row[3],
        "snmp_status": row[4],
        "sys_name": row[5],
        "sys_descr": row[6],
        "sys_object_id": row[7],
        "sys_uptime": row[8],
        "detected_vendor": row[9],
        "suggested_template_id": row[10],
        "suggested_template_slug": row[11],
        "suggested_template_name": row[12],
        "already_registered": bool(row[13]),
        "existing_host_id": row[14],
        "imported_host_id": row[15],
        "raw": row[16] or {},
        "created_at": to_iso(row[17]),
    }


DISCOVERY_RESULT_SELECT = """
    id, run_id, ip, icmp_status, snmp_status, sys_name, sys_descr, sys_object_id,
    sys_uptime, detected_vendor, suggested_template_id, suggested_template_slug,
    suggested_template_name, already_registered, existing_host_id, imported_host_id,
    raw, created_at
"""


def discovery_run_row_to_dict(row, results: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
    return {
        "id": row[0],
        "cidr": row[1],
        "timeout_seconds": row[2],
        "retries": row[3],
        "use_icmp": bool(row[4]),
        "use_snmp": bool(row[5]),
        "snmp_community_masked": row[6],
        "status": row[7],
        "started_at": to_iso(row[8]),
        "finished_at": to_iso(row[9]),
        "total_ips": row[10],
        "active_hosts": row[11],
        "snmp_hosts": row[12],
        "imported_hosts": row[13],
        "error": row[14],
        "requested_by": row[15],
        "audit": row[16] or {},
        "results": results or [],
    }


def list_discovery_results(cur, run_id: int) -> list[dict[str, Any]]:
    cur.execute(
        f"""
        SELECT {DISCOVERY_RESULT_SELECT}
        FROM network_discovery_results
        WHERE run_id=%s
        ORDER BY already_registered, ip
        """,
        (run_id,),
    )
    return [discovery_result_row_to_dict(row) for row in cur.fetchall()]


def get_or_create_discovery_group_id(cur) -> Optional[int]:
    if not has_host_groups_schema(cur):
        return None
    cur.execute("SELECT id FROM host_groups WHERE slug=%s OR path=%s LIMIT 1", ("discovery", "discovery"))
    row = cur.fetchone()
    if row is not None:
        return row[0]
    cur.execute(
        """
        INSERT INTO host_groups (name, slug, parent_id, path, tags, enabled)
        VALUES (%s, %s, NULL, %s, %s, true)
        RETURNING id
        """,
        ("Discovery", "discovery", "discovery", psycopg.types.json.Json({"source": "network_discovery"})),
    )
    return cur.fetchone()[0]


def get_fallback_host_group_id(cur) -> Optional[int]:
    if not has_host_groups_schema(cur):
        return None
    cur.execute("SELECT id FROM host_groups WHERE slug=%s OR path=%s LIMIT 1", ("discovery", "discovery"))
    row = cur.fetchone()
    if row is not None:
        return row[0]
    cur.execute("SELECT id FROM host_groups WHERE slug=%s OR path=%s LIMIT 1", ("lab", "lab"))
    row = cur.fetchone()
    if row is not None:
        return row[0]
    return get_or_create_discovery_group_id(cur)


def discovery_protocol_tags(result: dict[str, Any]) -> dict[str, bool]:
    return {
        "icmp": result.get("icmp_status") == "up",
        "snmp": result.get("snmp_status") == "up",
        "tcp": False,
        "syslog": result.get("snmp_status") == "up",
    }


def discovery_template_fallback(result: dict[str, Any]) -> dict[str, Optional[str]]:
    suggested_slug = str(result.get("suggested_template_slug") or "").strip() or None
    suggested_name = str(result.get("suggested_template_name") or "").strip() or None
    if suggested_slug or suggested_name:
        return {
            "template_slug": suggested_slug,
            "template_name": suggested_name,
        }

    if result.get("snmp_status") == "up":
        return {
            "template_slug": "generic-snmp-switch",
            "template_name": "Generic SNMP Switch",
        }

    return {
        "template_slug": "icmp-only",
        "template_name": "ICMP Only",
    }


def import_discovery_result(
    cur,
    result_id: int,
    group_id: Optional[int],
    enable_host: bool = True,
    snmp_community: Optional[str] = None,
) -> Optional[int]:
    cur.execute(
        f"""
        SELECT {DISCOVERY_RESULT_SELECT}
        FROM network_discovery_results
        WHERE id=%s
        """,
        (result_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Resultado de discovery não encontrado.")
    result = discovery_result_row_to_dict(row)
    if result["already_registered"] or result["existing_host_id"]:
        return result["existing_host_id"]
    if result["imported_host_id"]:
        return result["imported_host_id"]

    current_host = find_host_by_name_or_ip(cur, result.get("sys_name") or "", result["ip"])
    if current_host is not None:
        cur.execute(
            """
            UPDATE network_discovery_results
            SET already_registered=true,
                existing_host_id=%s,
                raw = COALESCE(raw, '{}'::jsonb) || %s::jsonb
            WHERE id=%s
            """,
            (
                current_host["id"],
                psycopg.types.json.Json({"deduplicated_on_import": True}),
                result_id,
            ),
        )
        return int(current_host["id"])

    target_group_id = group_id if group_id is not None else get_fallback_host_group_id(cur)
    template_id = result["suggested_template_id"]
    if template_id is None:
        fallback_slug = "generic-snmp-switch" if result["snmp_status"] == "up" else "icmp-only"
        template_id = get_template_id_by_slug(cur, result.get("suggested_template_slug") or fallback_slug)
    if template_id is None:
        template_id = get_template_id_by_slug(cur, "icmp-only")
    if template_id is None:
        template_id = get_template_id_by_slug(cur, "generic-snmp-switch")
    snmp_profile = {}
    if result["snmp_status"] == "up":
        snmp_profile = {
            "enabled": True,
            "version": "v2c",
            "community": snmp_community or "public",
            "port": 161,
            "timeout": 1,
            "retries": 1,
            "community_source": "discovery_import",
        }
    template_fallback = discovery_template_fallback(result)
    tags = {
        "source": "network_discovery",
        "discovery_source": "network_discovery",
        "status": "discovered",
        "detected_vendor": result["detected_vendor"],
        "sys_object_id": result["sys_object_id"],
        "snmp_expected": result["snmp_status"] == "up",
        "icmp_expected": result["icmp_status"] == "up",
        "protocols_enabled": discovery_protocol_tags(result),
        "suggested_template_slug": template_fallback["template_slug"],
        "suggested_template_name": template_fallback["template_name"],
    }
    name = result["sys_name"] or f"host-{result['ip']}"
    cur.execute(
        f"""
        INSERT INTO {ASSETS_TABLE} (name, ip, snmp_profile, tags, group_id, template_id, enabled)
        VALUES (%s, %s::inet, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            name,
            result["ip"],
            psycopg.types.json.Json(snmp_profile),
            psycopg.types.json.Json(tags),
            target_group_id,
            template_id,
            enable_host,
        ),
    )
    host_id = cur.fetchone()[0]
    if template_id:
        copy_template_items_to_host(cur, host_id, template_id)
    cur.execute(
        """
        UPDATE network_discovery_results
        SET imported_host_id=%s
        WHERE id=%s
        """,
        (host_id, result_id),
    )
    cur.execute(
        """
        UPDATE network_discovery_runs
        SET imported_hosts = imported_hosts + 1
        WHERE id = %s
        """,
        (result["run_id"],),
    )
    return host_id


def normalize_collect_protocol(value: Optional[str]) -> str:
    protocol = str(value or "all").strip().lower()
    if protocol not in {"icmp", "snmp", "all"}:
        raise HTTPException(status_code=400, detail="protocol must be one of: icmp, snmp or all")
    return protocol


def queue_collection_request(cur, asset_id: int, protocol: str) -> dict[str, Any]:
    if not has_collection_requests_schema(cur):
        raise HTTPException(status_code=503, detail="A fila de coleta sob demanda ainda não foi inicializada no banco.")

    normalized_protocol = normalize_collect_protocol(protocol)
    protocols = ("icmp", "snmp") if normalized_protocol == "all" else (normalized_protocol,)
    created_protocols: list[str] = []
    existing_requested_at = None

    for requested_protocol in protocols:
        cur.execute(
            """
            SELECT requested_at
            FROM collection_requests
            WHERE asset_id = %s
              AND status = 'pending'
              AND protocol = %s
            ORDER BY requested_at DESC
            LIMIT 1
            """,
            (asset_id, requested_protocol),
        )
        existing = cur.fetchone()
        if existing is not None:
            existing_requested_at = existing_requested_at or existing[0]
            continue

        cur.execute(
            """
            INSERT INTO collection_requests (asset_id, protocol, status, details)
            VALUES (%s, %s, 'pending', %s)
            RETURNING requested_at
            """,
            (
                asset_id,
                requested_protocol,
                psycopg.types.json.Json({"requested_by": "ui"}),
            ),
        )
        requested_at = cur.fetchone()[0]
        existing_requested_at = existing_requested_at or requested_at
        created_protocols.append(requested_protocol)

    queued = bool(created_protocols)
    if queued:
        message = (
            "Solicitação de coleta registrada para ICMP e SNMP."
            if normalized_protocol == "all"
            else f"Solicitação de coleta registrada para {normalized_protocol.upper()}."
        )
    else:
        message = "Já existe uma coleta sob demanda pendente para este host."

    return {
        "asset_id": asset_id,
        "protocol": normalized_protocol,
        "queued": queued,
        "status": "pending",
        "requested_at": to_iso(existing_requested_at) or "",
        "message": f"{message} Os pollers vão processar o pedido no próximo ciclo disponível.",
    }


def get_host_record(cur, host_id: int) -> dict[str, Any]:
    groups_ready = has_host_groups_schema(cur)
    templates_ready = has_monitoring_templates_schema(cur)
    collection_policy_ready = has_assets_collection_policy_schema(cur)
    query = (
        f"SELECT {', '.join(build_host_select_parts(groups_ready, templates_ready, collection_policy_ready))} "
        f"FROM {ASSETS_TABLE} a"
    )

    if groups_ready:
        query += " LEFT JOIN host_groups g ON g.id = a.group_id"

    if templates_ready:
        query += " LEFT JOIN monitoring_templates t ON t.id = a.template_id"

    query += " WHERE a.id = %s"

    cur.execute(query, (host_id,))
    row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Host não encontrado.")

    return host_row_to_dict(row, groups_ready, templates_ready, collection_policy_ready)


def to_iso(value) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat()


def normalize_status_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return str(value).strip().lower() or None


def normalize_severity_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return str(value).strip().lower() or None


def prediction_severity(score: Optional[float]) -> str:
    numeric = float(score or 0)
    if numeric >= 0.90:
        return "critical"
    if numeric >= 0.75:
        return "high"
    if numeric >= 0.50:
        return "warning"
    if numeric >= 0.25:
        return "medium"
    return "info"


def severity_rank(value: Optional[str]) -> int:
    ranks = {
        "critical": 6,
        "high": 5,
        "warning": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "notice": 1,
    }
    return ranks.get(normalize_severity_value(value) or "", 0)


def severity_rank_sql(column: str) -> str:
    return f"""
        CASE LOWER(COALESCE({column}, ''))
            WHEN 'critical' THEN 6
            WHEN 'high' THEN 5
            WHEN 'warning' THEN 4
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 2
            WHEN 'info' THEN 1
            WHEN 'notice' THEN 1
            ELSE 0
        END
    """


def parse_datetime_filter(value: Optional[str], *, end_of_day: bool = False):
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    try:
        if "T" in raw or " " in raw:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            parsed_date = datetime.strptime(raw, "%Y-%m-%d").date()
            parsed = datetime.combine(
                parsed_date,
                time.max if end_of_day else time.min,
                tzinfo=timezone.utc,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid datetime filter: {raw}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def host_health_status(
    enabled: bool,
    last_alive_value: Optional[float],
    last_collection_at,
    open_incidents: Optional[list[dict[str, Any]]] = None,
    *,
    icmp_current_ok: Optional[bool] = None,
    snmp_current_ok: Optional[bool] = None,
    snmp_expected_current: bool = True,
    loop_current_active: bool = False,
) -> tuple[str, str]:
    if not enabled:
        return "inactive", "Cadastro desativado"
    incident_items = open_incidents or []
    def incident_kind(item: dict[str, Any]) -> str:
        return str(item.get("problem_type") or item.get("incident_type") or "").strip().lower()

    availability_kinds = {
        "host_down",
        "icmp_collection_silence",
        "collection_silence",
        "host_unavailable",
        "unavailable",
    }
    snmp_kinds = {"snmp_collection_silence"}
    loop_kinds = {"loop_risk"}
    incident_types = {incident_kind(item) for item in incident_items}
    titles = [str(item.get("title") or "").strip() for item in incident_items if item.get("title")]

    alive_ok = icmp_current_ok
    if alive_ok is None and last_alive_value is not None:
        alive_ok = float(last_alive_value) >= 1

    if loop_current_active and any(item in incident_types for item in loop_kinds):
        return "critical", titles[0] if titles else "Incidente critico aberto"

    if last_alive_value is not None and float(last_alive_value) < 1:
        return "unavailable", "ICMP indica host indisponivel"

    stale_current_incidents = availability_kinds | snmp_kinds
    if not loop_current_active:
        stale_current_incidents = stale_current_incidents | loop_kinds
    relevant_incidents = [
        item for item in incident_items
        if incident_kind(item) not in stale_current_incidents
    ]
    critical_relevant = [
        item for item in relevant_incidents
        if str(item.get("severity") or "").strip().lower() == "critical"
    ]
    high_relevant = [
        item for item in relevant_incidents
        if str(item.get("severity") or "").strip().lower() in {"high", "warning"}
    ]

    if alive_ok is True:
        if snmp_expected_current and snmp_current_ok is False:
            return "degraded", "ICMP OK, mas sem telemetria SNMP recente"
        if critical_relevant:
            return "critical", str(critical_relevant[0].get("title") or "Incidente critico aberto")
        if high_relevant:
            return "degraded", str(high_relevant[0].get("title") or "Incidente operacional aberto")
        return "healthy", "Telemetria atual sem incidente ativo relevante"

    if any(item in incident_types for item in availability_kinds):
        return "critical", titles[0] if titles else "Sem disponibilidade recente"
    if snmp_expected_current and any(item in incident_types for item in snmp_kinds):
        return "degraded", titles[0] if titles else "Sem telemetria SNMP recente"
    if last_alive_value is None and last_collection_at is None:
        return "unavailable", "Sem ICMP/SNMP recente"
    if critical_relevant:
        return "critical", str(critical_relevant[0].get("title") or "Incidente critico aberto")
    if high_relevant:
        return "degraded", titles[0] if titles else "Incidente operacional aberto"
    return "healthy", "Sem incidente aberto relevante"


def latest_timestamp(*values):
    present = [value for value in values if value is not None]
    if not present:
        return None
    return max(present)


def has_legacy_ping_schema(cur) -> bool:
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = %s
        """,
        (PING_TABLE,),
    )
    columns = {row[0] for row in cur.fetchall()}
    required = {"host_id", "rtt_ms", "loss_pct", "ts"}
    return required.issubset(columns)

# ====== MODELOS EXISTENTES ======
class HostIn(BaseModel):
    name: str
    ip: IPvAnyAddress
    snmp_profile: Optional[dict] = None
    tags: Optional[dict] = None
    group_id: Optional[int] = None
    template_id: Optional[int] = None
    collection_policy_override: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

class HostOut(HostIn):
    id: int
    discovery_source: Optional[str] = None
    group_name: Optional[str] = None
    group_path: Optional[str] = None
    template_name: Optional[str] = None
    template_slug: Optional[str] = None
    template_asset_type: Optional[str] = None
    template_vendor: Optional[str] = None
    template_family: Optional[str] = None
    template_summary: Optional[str] = None
    health_status: Optional[str] = None
    health_reason: Optional[str] = None
    last_collection_at: Optional[str] = None
    last_activity_at: Optional[str] = None
    open_incidents: int = 0
    max_incident_severity: Optional[str] = None
    last_incident_title: Optional[str] = None
    last_incident_at: Optional[str] = None
    loop_risk_score: Optional[float] = None
    loop_risk_ts: Optional[str] = None
    collection_policy_resolved: dict[str, Any] = Field(default_factory=dict)
    collection_policy_sources: dict[str, str] = Field(default_factory=dict)
    collection_policy_source: Optional[str] = None
    collection_policy_source_labels: dict[str, str] = Field(default_factory=dict)
    last_icmp_collection_at: Optional[str] = None
    last_snmp_collection_at: Optional[str] = None
    next_icmp_collection_at: Optional[str] = None
    next_snmp_collection_at: Optional[str] = None


class HostGroupIn(BaseModel):
    name: str
    parent_id: Optional[int] = None
    tags: Optional[dict] = None
    enabled: bool = True


class HostGroupOut(BaseModel):
    id: int
    name: str
    slug: str
    parent_id: Optional[int] = None
    path: str
    tags: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class TemplateProfileOut(BaseModel):
    profile_id: int
    name: str
    display_name: str
    kind: str
    description: Optional[str] = None
    config: dict[str, Any] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    sort_order: int = 0


class MonitoringTemplateOut(BaseModel):
    id: int
    name: str
    slug: str
    asset_type: str
    vendor: Optional[str] = None
    family: Optional[str] = None
    summary: Optional[str] = None
    definition: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    preview: dict[str, Any] = Field(default_factory=dict)
    collection_policy: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    profiles: List[TemplateProfileOut] = Field(default_factory=list)


class MonitoringTemplatePreviewOut(BaseModel):
    id: int
    name: str
    slug: str
    asset_type: str
    vendor: Optional[str] = None
    family: Optional[str] = None
    summary: Optional[str] = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    preview: dict[str, Any] = Field(default_factory=dict)
    collection_policy: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    profiles: List[TemplateProfileOut] = Field(default_factory=list)


class CollectionPolicyIn(BaseModel):
    icmp_interval_sec: Optional[int] = None
    snmp_interval_sec: Optional[int] = None
    tcp_interval_sec: Optional[int] = None
    timeout_sec: Optional[int] = None
    retries: Optional[int] = None
    history_retention_days: Optional[int] = None
    trend_retention_days: Optional[int] = None
    log_retention_days: Optional[int] = None
    incident_retention_days: Optional[int] = None
    notification_retention_days: Optional[int] = None
    audit_retention_days: Optional[int] = None


class MonitoringItemIn(BaseModel):
    display_name: Optional[str] = None
    oid: Optional[str] = None
    unit: Optional[str] = None
    enabled: Optional[bool] = None
    poll_interval_seconds: Optional[int] = None
    timeout_seconds: Optional[int] = None
    retries: Optional[int] = None
    history_retention_days: Optional[int] = None
    trend_retention_days: Optional[int] = None
    log_retention_days: Optional[int] = None
    config: Optional[dict[str, Any]] = None


class MonitoringItemToggleIn(BaseModel):
    enabled: bool


class MonitoringItemOut(BaseModel):
    id: int
    host_id: Optional[int] = None
    template_id: Optional[int] = None
    source: str = "template"
    protocol: str
    item_key: str
    display_name: str
    oid: Optional[str] = None
    unit: Optional[str] = None
    enabled: bool
    poll_interval_seconds: int
    timeout_seconds: int
    retries: int
    history_retention_days: int
    trend_retention_days: int
    log_retention_days: int
    last_collected_at: Optional[str] = None
    last_error: Optional[str] = None
    config: dict[str, Any] = Field(default_factory=dict)


class ApplyTemplateIn(BaseModel):
    template_id: int
    copy_items_to_host: bool = True
    replace_profiles: bool = True


class NetworkDiscoveryScanIn(BaseModel):
    cidr: str
    timeout_seconds: int = Field(default=1, ge=1, le=5)
    retries: int = Field(default=1, ge=0, le=3)
    use_icmp: bool = True
    use_snmp: bool = True
    snmp_community: str = Field(default="public", min_length=0, max_length=120)
    requested_by: Optional[str] = None


class NetworkDiscoveryImportIn(BaseModel):
    result_ids: List[int]
    group_id: Optional[int] = None
    enable_hosts: bool = True
    snmp_community: Optional[str] = Field(default=None, max_length=120)


class NetworkDiscoveryResultOut(BaseModel):
    id: int
    run_id: int
    ip: str
    icmp_status: str
    snmp_status: str
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None
    sys_object_id: Optional[str] = None
    sys_uptime: Optional[str] = None
    detected_vendor: Optional[str] = None
    suggested_template_id: Optional[int] = None
    suggested_template_slug: Optional[str] = None
    suggested_template_name: Optional[str] = None
    already_registered: bool = False
    existing_host_id: Optional[int] = None
    imported_host_id: Optional[int] = None
    raw: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None


class NetworkDiscoveryRunOut(BaseModel):
    id: int
    cidr: str
    timeout_seconds: int
    retries: int
    use_icmp: bool
    use_snmp: bool
    snmp_community_masked: Optional[str] = None
    status: str
    started_at: str
    finished_at: Optional[str] = None
    total_ips: int = 0
    active_hosts: int = 0
    snmp_hosts: int = 0
    imported_hosts: int = 0
    error: Optional[str] = None
    requested_by: Optional[str] = None
    audit: dict[str, Any] = Field(default_factory=dict)
    results: List[NetworkDiscoveryResultOut] = Field(default_factory=list)


class SyslogInterfaceCorrelationOut(BaseModel):
    id: int
    asset_id: int
    syslog_event_id: int
    interface_id: Optional[int] = None
    ifindex: Optional[int] = None
    normalized_iface: Optional[str] = None
    confidence: float
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    event_ts: Optional[str] = None
    event_severity: Optional[str] = None
    event_subsystem: Optional[str] = None
    event_message: Optional[str] = None
    ifdescr: Optional[str] = None
    if_name: Optional[str] = None
    if_alias: Optional[str] = None


class CollectNowIn(BaseModel):
    protocol: str = "all"


class CollectNowOut(BaseModel):
    asset_id: int
    protocol: str
    queued: bool = True
    status: str
    requested_at: str
    message: str

# ====== MODELOS DE PROFILES ======
class ProfileOut(BaseModel):
    id: int
    name: str
    display_name: str
    kind: str
    description: Optional[str] = None
    config: dict[str, Any] = {}
    enabled: bool

class HostProfileOut(BaseModel):
    profile_id: int
    name: str
    display_name: str
    kind: str
    description: Optional[str] = None
    config: dict[str, Any] = {}
    params: dict[str, Any] = {}
    enabled: bool

class HostProfileUpdateItem(BaseModel):
    profile_id: int
    params: dict[str, Any] = {}
    enabled: bool = True

class HostProfilesUpdate(BaseModel):
    profiles: List[HostProfileUpdateItem]

# ====== MODELOS NOVOS (para /metrics/overview) ======
class HostRow(BaseModel):
    id: int
    name: str
    ip: str
    enabled: bool
    last_rtt_ms: Optional[float] = None
    last_loss_pct: Optional[float] = None

class Overview(BaseModel):
    total_hosts: int
    active_hosts: int
    inactive_hosts: int
    avg_rtt_ms: Optional[float] = None
    avg_loss_pct: Optional[float] = None
    hosts: List[HostRow]


class CapacityEstimateOut(BaseModel):
    total_hosts: int = 0
    total_items: int = 0
    avg_items_per_host: float = 0.0
    avg_collection_interval_sec: float = 0.0
    avg_sample_bytes: int = 256
    avg_history_retention_days: float = 30.0
    avg_trend_retention_days: float = 90.0
    avg_log_retention_days: float = 14.0
    avg_incident_retention_days: float = 180.0
    avg_notification_retention_days: float = 90.0
    avg_audit_retention_days: float = 365.0
    estimated_storage_per_day_bytes: int = 0
    estimated_storage_per_month_bytes: int = 0
    estimated_storage_for_retention_bytes: int = 0
    recommended_disk_bytes: int = 0
    estimated_components: dict[str, int] = Field(default_factory=dict)
    scenarios: List[dict[str, Any]] = Field(default_factory=list)
    assumptions: dict[str, Any] = Field(default_factory=dict)
    formula: str = ""

class DiscoveredInterfaceOut(BaseModel):
    id: int
    asset_id: int
    ifindex: int
    ifdescr: str
    if_name: Optional[str] = None
    if_alias: Optional[str] = None
    admin_status: Optional[int] = None
    oper_status: Optional[int] = None
    last_seen_at: Optional[str] = None
    last_change: Optional[str] = None
    speed_bps: Optional[int] = None
    mac_address: Optional[str] = None
    last_in_octets: Optional[float] = None
    last_out_octets: Optional[float] = None
    last_in_errors: Optional[float] = None
    last_out_errors: Optional[float] = None
    last_in_discards: Optional[float] = None
    last_out_discards: Optional[float] = None
    last_in_bps: Optional[float] = None
    last_out_bps: Optional[float] = None
    last_error: Optional[str] = None
    selected: bool = True


class DiscoveryResponse(BaseModel):
    host_id: int
    interfaces: List[DiscoveredInterfaceOut]

class UpdateDiscoveredInterfaceSelectionIn(BaseModel):
    selected: bool

class IncidentOut(BaseModel):
    id: int
    opened_at: str
    last_seen_at: str
    status: str
    hostname: str
    src_ip: str
    incident_type: str
    key: str
    severity: str
    title: str
    asset_id: Optional[int] = None
    group_id: Optional[int] = None
    group_name: Optional[str] = None
    group_path: Optional[str] = None
    template_id: Optional[int] = None
    template_name: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


class AlertProblemIn(BaseModel):
    device_name: str = Field(min_length=1, max_length=255)
    device_ip: IPvAnyAddress
    problem_type: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=2000)
    severity: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL|low|medium|high|critical)$")
    details: dict[str, Any] = Field(default_factory=dict)
    detected_at: Optional[datetime] = None


class AlertResolveIn(BaseModel):
    send_recovery_notification: bool = True
    manual_reason: Optional[str] = None
    resolution_source: Optional[str] = None


class AlertAcknowledgeIn(BaseModel):
    note: Optional[str] = None


class AlertNotifyIn(BaseModel):
    force: bool = False


class AlertResultOut(BaseModel):
    incident_id: int
    status: str
    severity: str
    notification_sent: bool
    notification_suppressed: bool
    created: bool
    updated: bool
    incident: dict[str, Any] = Field(default_factory=dict)
    notifications: List[dict[str, Any]] = Field(default_factory=list)


class AlertNotificationOut(BaseModel):
    id: int
    incident_id: Optional[int] = None
    channel: str
    provider: Optional[str] = None
    delivery_status: str
    error: Optional[str] = None
    sent_at: str


class AlertIncidentOut(BaseModel):
    id: int
    device_name: str
    device_ip: str
    problem_type: str
    description: str
    severity: str
    status: str
    first_detected_at: Optional[str] = None
    last_detected_at: Optional[str] = None
    resolved_at: Optional[str] = None
    notification_sent: bool
    updated_at: Optional[str] = None
    latest_notification: Optional[dict[str, Any]] = None
    resolution_source: Optional[str] = None
    recovery_evidence: Optional[str] = None


class AlertSummaryOut(BaseModel):
    open_alerts: int = 0
    critical_open_alerts: int = 0
    notifications_sent_today: int = 0
    notifications_suppressed_today: int = 0
    active_channels: int = 0
    last_alert: Optional[dict[str, Any]] = None


class AlertChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    provider: str
    enabled: bool = True
    min_severity: str = Field(default="LOW", pattern="^(LOW|MEDIUM|HIGH|CRITICAL|low|medium|high|critical)$")
    config: dict[str, Any] = Field(default_factory=dict)


class AlertChannelToggleIn(BaseModel):
    enabled: bool


class AlertChannelOut(BaseModel):
    id: int
    name: str
    provider: str
    enabled: bool
    min_severity: str
    config: dict[str, Any] = Field(default_factory=dict)
    last_test_status: Optional[str] = None
    last_test_error: Optional[str] = None
    last_test_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class AlertChannelTestOut(BaseModel):
    channel_id: int
    channel: str
    provider: str
    delivery_status: str
    error: Optional[str] = None
    sent_at: str


class SyslogEventOut(BaseModel):
    id: int
    ts: str
    hostname: str
    src_ip: str
    asset_id: Optional[int] = None
    group_id: Optional[int] = None
    group_name: Optional[str] = None
    group_path: Optional[str] = None
    template_id: Optional[int] = None
    template_name: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    event_id: Optional[int] = None
    severity: Optional[str] = None
    subsystem: Optional[str] = None
    slot: Optional[str] = None
    iface: Optional[str] = None
    message: str
    raw: str


class PredictionOut(BaseModel):
    ts: str
    asset_id: int
    metric: str
    key: str
    score: float
    severity: Optional[str] = None
    z: Optional[float] = None
    value: Optional[float] = None
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None
    details: dict[str, Any] = Field(default_factory=dict)


class RecentSignalOut(BaseModel):
    id: str
    ts: str
    source: str
    signal_type: str
    title: str
    message: str
    hostname: str
    src_ip: Optional[str] = None
    asset_id: Optional[int] = None
    group_id: Optional[int] = None
    group_name: Optional[str] = None
    group_path: Optional[str] = None
    template_id: Optional[int] = None
    template_name: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    subsystem: Optional[str] = None
    iface: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


class ReportEventOut(BaseModel):
    id: str
    ts: str
    severity: str
    source: str
    source_label: str
    host_name: Optional[str] = None
    host_ip: Optional[str] = None
    context_name: Optional[str] = None
    group_name: Optional[str] = None
    template_name: Optional[str] = None
    title: str
    details: str
    status: Optional[str] = None
    signal_type: Optional[str] = None
    asset_id: Optional[int] = None
    group_id: Optional[int] = None
    template_id: Optional[int] = None


class PredictionsSummaryOut(BaseModel):
    anomaly_count: int
    max_score: Optional[float] = None
    latest_ts: Optional[str] = None
    loop_risk_open: int = 0
    loop_risk_total: int = 0


class HostPredictionsOut(BaseModel):
    host_id: int
    host_name: str
    summary: PredictionsSummaryOut
    loop_risk_incidents: List[IncidentOut] = Field(default_factory=list)
    anomaly_scores: List[PredictionOut] = Field(default_factory=list)


class MetricOut(BaseModel):
    ts: str
    asset_id: int
    metric: str
    value: float
    labels: dict = {}


class LabBootstrapOut(BaseModel):
    host_id: int
    host_name: str
    host_ip: str
    profiles_applied: List[str]
    selected_interface: str
    interfaces_discovered: int
    template_name: Optional[str] = None


class GrafanaDashboardOut(BaseModel):
    dashboard_key: str
    title: str
    description: Optional[str] = None
    kind: str
    owner_type: str
    owner_id: Optional[int] = None
    grafana_uid: str
    slug: str
    embed_url: str
    view_url: str
    edit_url: Optional[str] = None
    variables: dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    height: int = 720


class AIInsightTriggerIn(BaseModel):
    refresh: bool = False


class TechnicalSummaryIn(BaseModel):
    host_id: Optional[int] = None
    incident_id: Optional[int] = None
    refresh: bool = False


class AIInsightOut(BaseModel):
    id: int
    target_type: str
    target_id: int
    insight_type: str
    status: str
    model: Optional[str] = None
    title: str
    content_md: str
    content_json: dict[str, Any] = Field(default_factory=dict)
    evidence_json: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    expires_at: Optional[str] = None
    cached: bool = False


class AIChatMessageIn(BaseModel):
    role: str
    content: str


class AIChatRequestIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    host_id: Optional[int] = None
    incident_id: Optional[int] = None
    hours: int = Field(default=24, ge=1, le=168)
    history: List[AIChatMessageIn] = Field(default_factory=list)
    response_mode: str = "auto"


class AIChatOut(BaseModel):
    model_config = {"protected_namespaces": ()}

    model: Optional[str] = None
    reply_md: str
    generated_at: str
    context_scope: dict[str, Any] = Field(default_factory=dict)
    evidence_json: dict[str, Any] = Field(default_factory=dict)
    answer_source: str = "deterministic"
    model_used: Optional[str] = None
    intent_detected: Optional[str] = None
    response_mode: str = "auto"
    llm_latency_ms: Optional[int] = None
    fallback_reason: Optional[str] = None


AI_RESPONSE_MODES = {"auto", "fast", "llm", "hybrid"}
AI_CHAT_INTENTS = {
    "status_check",
    "gratitude",
    "help",
    "incident_analysis",
    "environment_summary",
    "troubleshooting",
    "host_question",
    "general_question",
}


AI_CHAT_COMMAND_PREFIXES = ("/netguard", "/ia", "/perguntar", "/status", "/resumo")


def normalize_ai_response_mode(value: Optional[str]) -> str:
    mode = str(value or "auto").strip().lower()
    return mode if mode in AI_RESPONSE_MODES else "auto"


def strip_ai_chat_command_prefix(message: str) -> str:
    value = str(message or "").strip()
    if not value:
        return ""
    lowered = value.lower()
    for prefix in AI_CHAT_COMMAND_PREFIXES:
        if lowered == prefix:
            return ""
        if lowered.startswith(prefix + " "):
            return value.split(maxsplit=1)[1].strip()
    return value


def is_gratitude_message(message: str) -> bool:
    normalized = normalize_chat_message(strip_ai_chat_command_prefix(message))
    if not normalized:
        return False

    exact_values = {
        "obrigado",
        "obrigada",
        "obg",
        "brigado",
        "brigada",
        "valeu",
        "vlw",
        "thanks",
        "thank you",
        "ok",
        "ok obrigado",
        "ok obrigada",
        "beleza",
        "blz",
        "show",
        "perfeito",
        "entendi",
        "entendido",
        "compreendi",
        "certo",
        "fechado",
        "ta bom",
        "esta bom",
    }
    if normalized in exact_values:
        return True

    words = normalized.split()
    gratitude_tokens = {
        "obrigado",
        "obrigada",
        "obg",
        "brigado",
        "brigada",
        "valeu",
        "vlw",
        "entendi",
        "entendido",
        "perfeito",
        "show",
    }
    return len(words) <= 5 and any(word in gratitude_tokens for word in words)


def is_short_operational_command(message: str) -> bool:
    normalized = normalize_chat_message(strip_ai_chat_command_prefix(message))
    if not normalized:
        return True

    exact_commands = {
        "status",
        "health",
        "saude",
        "listar hosts",
        "lista hosts",
        "hosts",
        "listar incidentes",
        "lista incidentes",
        "incidentes",
        "quantidade de hosts",
        "qtd hosts",
        "quantos hosts",
        "uptime",
        "versao",
        "versao do netguard",
        "version",
        "ajuda",
        "help",
        "comandos",
    }
    if normalized in exact_commands:
        return True

    command_patterns = (
        r"^quantos hosts( existem| tenho| cadastrados)?$",
        r"^quantos incidentes( existem| ativos| abertos)?$",
        r"^listar (os )?hosts$",
        r"^listar (os )?incidentes$",
    )
    return any(re.match(pattern, normalized) for pattern in command_patterns)


def classify_ai_chat_intent(message: str, context: dict[str, Any]) -> str:
    clean_message = strip_ai_chat_command_prefix(message)
    normalized = normalize_chat_message(clean_message)
    if not normalized:
        return "status_check"

    if is_gratitude_message(clean_message):
        return "gratitude"

    if normalized in {"ajuda", "help", "comandos"}:
        return "help"

    if context.get("scope_context", {}).get("host_id") is not None:
        return "host_question"
    if context.get("scope_context", {}).get("incident_id") is not None:
        return "incident_analysis"

    if is_short_operational_command(clean_message):
        return "status_check"

    incident_type_terms = (
        "snmp collection silence",
        "icmp collection silence",
        "collection silence",
        "host down",
        "loop risk",
        "loop l2",
        "broadcast storm",
        "mac flapping",
        "interface flap",
    )
    if "incidente" in normalized or any(term in normalized for term in incident_type_terms):
        return "incident_analysis"

    incident_terms = (
        "do que se trata",
        "do que se trata esse alerta",
        "do que se trata este alerta",
        "do que se trata esse problema",
        "o que significa",
        "o que quer dizer",
        "explica esse incidente",
        "explique esse incidente",
        "explica esse alerta",
        "explique esse alerta",
        "explique o incidente",
        "explique os incidentes",
        "incidentes ativos",
        "incidente ativo",
        "por que esse incidente",
        "porque esse incidente",
        "por que abriu",
        "por que foi aberto",
        "isso e grave",
        "isso eh grave",
        "e grave",
        "eh grave",
        "switch esta critico",
        "host esta critico",
        "esta critico",
        "critico",
    )
    if any(term in normalized for term in incident_terms):
        return "incident_analysis"

    environment_terms = (
        "como esta o ambiente",
        "como est o ambiente",
        "como ta o ambiente",
        "estado do ambiente",
        "situacao do ambiente",
        "ambiente agora",
        "ambiente atual",
        "maior risco",
        "risco agora",
        "risco atual",
        "prioridade agora",
        "principal problema",
        "problema principal",
    )
    if any(term in normalized for term in environment_terms):
        return "environment_summary"
    if "ambiente" in normalized and any(term in normalized for term in ("como", "estado", "situacao", "atual", "agora", "risco")):
        return "environment_summary"

    troubleshooting_terms = (
        "o que devo corrigir",
        "corrigir primeiro",
        "o que faco",
        "o que eu faco",
        "o que fazer",
        "acao recomendada",
        "proximo passo",
        "troubleshooting",
        "resolver",
        "corrigir",
        "validar",
    )
    if any(term in normalized for term in troubleshooting_terms):
        return "troubleshooting"

    if "host" in normalized or "switch" in normalized or "dispositivo" in normalized:
        return "host_question"

    return "general_question"


def should_use_conceptual_fast_reply(message: str, context: dict[str, Any], intent: str) -> bool:
    return False


def choose_ai_response_mode(requested_mode: str, intent: str, message: str, context: dict[str, Any]) -> str:
    requested = normalize_ai_response_mode(requested_mode)
    if requested != "auto":
        return requested
    if context.get("question_kind") == "greeting" or intent in {"status_check", "gratitude", "help"}:
        return "fast"
    return "hybrid"


def enrich_active_operational_brief_for_chat(context: dict[str, Any]) -> None:
    brief = context.get("active_operational_brief")
    if not isinstance(brief, dict):
        brief = {}
    environment_context = context.get("environment_context") or {}
    environment = environment_context.get("environment") or {}
    active_incidents = list(environment_context.get("active_incidents") or context.get("active_incidents") or [])
    recent_syslog = list(environment_context.get("recent_syslog") or [])
    recent_predictions = list(environment_context.get("recent_predictions") or [])

    if environment:
        brief["environment_state"] = {
            "total_hosts": environment.get("total_hosts"),
            "active_hosts": environment.get("active_hosts"),
            "inactive_hosts": environment.get("inactive_hosts"),
            "open_incidents": environment.get("open_incidents"),
            "open_loop_risk": environment.get("open_loop_risk"),
        }
    if active_incidents:
        brief["active_incidents"] = active_incidents[:6]
    if recent_syslog:
        brief["recent_syslog"] = recent_syslog[:4]
    if recent_predictions:
        brief["recent_anomalies"] = recent_predictions[:4]

    technical_evidence = []
    technical_evidence.extend(str(item) for item in list(brief.get("recent_evidence") or [])[:4])
    technical_evidence.extend(str(item) for item in list(brief.get("historical_evidence") or [])[:4])
    for item in active_incidents[:3]:
        label = incident_type_label(item.get("incident_type"), item.get("title"))
        technical_evidence.append(
            f"Incidente ativo: {label} em {item.get('hostname') or item.get('src_ip') or 'host desconhecido'}; severidade {item.get('severity') or '-'}."
        )
        incident_type = str(item.get("incident_type") or "").strip().lower()
        if incident_type == "snmp_collection_silence":
            technical_evidence.append(
                "Definição: snmp_collection_silence indica que o host deveria ter telemetria SNMP recente, mas o NetGuard não recebeu amostras SNMP dentro da janela esperada."
            )
        elif incident_type == "icmp_collection_silence":
            technical_evidence.append(
                "Definição: icmp_collection_silence indica ausência de amostras ICMP recentes para um host que deveria estar sendo verificado por disponibilidade."
            )
        elif incident_type == "host_down":
            technical_evidence.append(
                "Definição: host_down indica que o ativo deixou de responder ao sinal principal de disponibilidade no recorte monitorado."
            )
        elif incident_type == "loop_risk":
            technical_evidence.append(
                "Definição: loop_risk indica correlação de sinais compatíveis com risco de loop L2, como storm, STP, MAC flapping ou flap recorrente."
            )
    brief["technical_evidence"] = dedupe_text_items(technical_evidence)[:8]
    brief["probable_impact"] = brief.get("impact") or "Impacto não definido no contexto atual."
    actions = list(brief.get("immediate_actions") or [])
    brief["recommended_action"] = actions[0] if actions else "Manter acompanhamento e validar manualmente se surgirem novos sinais."
    confidence_basis = list(brief.get("confidence_basis") or [])
    evidence_count = len(brief.get("technical_evidence") or [])
    if evidence_count >= 3 and confidence_basis:
        confidence_level = "média-alta"
    elif evidence_count >= 1:
        confidence_level = "média"
    else:
        confidence_level = "baixa"
    brief["confidence_level"] = confidence_level
    context["active_operational_brief"] = brief


def build_status_check_reply(context: dict[str, Any]) -> str:
    environment_context = context.get("environment_context") or {}
    environment = environment_context.get("environment") or {}
    active_incidents = list(environment_context.get("active_incidents") or context.get("active_incidents") or [])
    brief = context.get("active_operational_brief") or {}

    lines = [
        "Status rápido do NetGuard:",
        f"- Hosts cadastrados: {environment.get('total_hosts') or 0}.",
        f"- Hosts ativos: {environment.get('active_hosts') or 0}; inativos: {environment.get('inactive_hosts') or 0}.",
        f"- Incidentes abertos: {environment.get('open_incidents') or 0}.",
        f"- Loop risk aberto: {environment.get('open_loop_risk') or 0}.",
    ]
    if active_incidents:
        lead = active_incidents[0]
        lines.append(
            f"- Maior atenção agora: {incident_type_label(lead.get('incident_type'), lead.get('title'))} em {lead.get('hostname') or lead.get('src_ip') or 'host desconhecido'}."
        )
    elif brief.get("current_state"):
        lines.append(f"- Leitura atual: {brief.get('current_state')}")
    else:
        lines.append("- Nenhum incidente ativo relevante foi encontrado no contexto carregado.")
    return "\n".join(lines)


def build_gratitude_chat_reply() -> str:
    return "De nada! Quando quiser, me manda a proxima pergunta sobre o ambiente, um alerta ou algum ponto da rede."


def build_help_chat_reply() -> str:
    return (
        "Você pode me perguntar pelo Telegram sobre o ambiente, incidentes, hosts e próximos passos. "
        "Exemplos: `/netguard como está o ambiente?`, `/netguard qual o maior risco agora?`, "
        "`/netguard explique os incidentes ativos`, `/netguard o que eu faço agora?` ou `/netguard status`."
    )


def build_deterministic_chat_reply(message: str, context: dict[str, Any], intent: str) -> str:
    if context.get("question_kind") == "greeting":
        return build_greeting_chat_reply(context)

    if intent == "gratitude":
        return build_gratitude_chat_reply()

    if intent == "help":
        return build_help_chat_reply()

    if intent == "status_check":
        return build_status_check_reply(context)

    fast_reply = build_fast_conceptual_chat_reply(message, context)
    if fast_reply:
        return fast_reply

    operational_reply = build_fast_operational_chat_reply(message, context)
    if operational_reply:
        return operational_reply

    return build_ai_unavailable_chat_reply(message, context, "Resposta determinística solicitada.")


def build_hybrid_ai_chat_prompt(message: str, context: dict[str, Any], history: list[dict[str, str]], intent: str) -> str:
    context_block = build_prompt_context_digest(context, prompt_mode="chat")
    history_lines: list[str] = []
    for item in history[-3:]:
        role = "Usuário" if str(item.get("role") or "").strip().lower() == "user" else "Assistente"
        content = str(item.get("content") or "").strip()
        if content:
            history_lines.append(f"{role}: {content}")
    history_block = "\n".join(history_lines) if history_lines else "Sem histórico anterior nesta sessão."

    return f"""
Você é o analista NOC do NetGuard. Responda em português do Brasil, com acentuação correta.

Intenção detectada: {intent}

Regras obrigatórias:
- responda exatamente a pergunta do usuário antes de ampliar a análise;
- se a pergunta pedir "do que se trata", explique o significado do incidente em vez de explicar só o protocolo;
- para tipos de incidente, cubra: o que é, por que abriu, impacto provável e o que validar;
- adapte o formato à pergunta; não use cabeçalhos fixos quando uma resposta natural curta for melhor;
- use os cabeçalhos Situação atual, Evidências, Risco e Ação recomendada apenas para perguntas de estado, risco, priorização ou troubleshooting;
- se houver ações imediatas no contexto, use essas ações; não responda só "monitorar" quando existir validação técnica concreta;
- para snmp_collection_silence, explique que é ausência de telemetria SNMP recente esperada e recomende validar se SNMP deveria estar ativo, credencial/community, UDP/161 e template/perfil aplicado;
- use somente as evidências presentes no contexto;
- limite a resposta a 120-180 palavras, salvo se o usuário pedir detalhes;
- use no máximo 4 bullets de ação;
- não invente estado, causa, métrica, topologia, comando executado ou resultado;
- priorize incidentes ativos e hosts habilitados;
- diferencie fato observado, inferência e limite quando necessário;
- seja curto, técnico e acionável;
- não recomende reset, reboot, automação ou mudança irreversível sem evidência explícita;
- se a pergunta for ampla, responda pelo maior risco operacional atual;
- se o usuário chamar algo de crítico mas o contexto indicar apenas degraded/high/attention, corrija o rótulo sem exagerar;
- não inclua seção de histórico da conversa na resposta final;

Histórico recente:
{history_block}

Pergunta:
{message.strip()}

Contexto operacional do NetGuard:
{context_block}
""".strip()


def clean_ai_chat_reply(text: str) -> str:
    content = str(text or "").strip()
    if not content:
        return content
    content = re.sub(
        r"\n{1,3}Hist[oó]rico recente:\s*(?:Sem hist[oó]rico anterior nesta sess[aã]o\.)?\s*$",
        "",
        content,
        flags=re.IGNORECASE,
    ).strip()
    return content


def normalize_limit(limit: int, *, default: int = 100, maximum: int = 1000) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def grafana_time_value(value, default_value: str) -> str:
    if value is None:
        return default_value

    if isinstance(value, str):
        parsed = parse_datetime_filter(value)
        if parsed is None:
            return default_value
        value = parsed

    return str(int(value.timestamp() * 1000))


def resolve_host_dashboard_key(host: dict[str, Any]) -> str:
    template_slug = str(host.get("template_slug") or "").strip().lower()
    template_asset_type = str(host.get("template_asset_type") or "").strip().lower()

    if template_slug == "linux-basic" or template_asset_type in {"linux", "server"}:
        return "host_linux"

    return "host_network"


def build_grafana_dashboard(
    dashboard_key: str,
    *,
    owner_type: str,
    owner_id: Optional[int] = None,
    variables: Optional[dict[str, Any]] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[list[str]] = None,
    context: Optional[dict[str, Any]] = None,
    from_ts=None,
    to_ts=None,
) -> dict[str, Any]:
    definition = GRAFANA_DASHBOARD_REGISTRY.get(dashboard_key)
    if definition is None:
        raise HTTPException(status_code=500, detail=f"Chave de dashboard do Grafana desconhecida: {dashboard_key}")

    query_params: dict[str, Any] = {
        "orgId": GRAFANA_ORG_ID,
        "theme": GRAFANA_THEME,
        "refresh": GRAFANA_REFRESH,
        "from": grafana_time_value(from_ts, "now-24h"),
        "to": grafana_time_value(to_ts, "now"),
    }

    for variable_name, variable_value in (variables or {}).items():
        if variable_value is None:
            continue
        query_params[f"var-{variable_name}"] = str(variable_value)

    dashboard_path = f"/d/{definition['uid']}/{definition['slug']}"
    view_url = f"{join_public_url(GRAFANA_PUBLIC_URL, dashboard_path)}?{urlencode(query_params)}"
    edit_params = {
        **query_params,
        "editview": "dashboard",
    }
    embed_params = {
        **query_params,
        "kiosk": "1",
    }
    edit_url = f"{join_public_url(GRAFANA_PUBLIC_URL, dashboard_path)}?{urlencode(edit_params)}"
    embed_url = f"{join_public_url(GRAFANA_PUBLIC_URL, dashboard_path)}?{urlencode(embed_params)}"

    return {
        "dashboard_key": dashboard_key,
        "title": title or definition["title"],
        "description": description or definition.get("description"),
        "kind": definition["kind"],
        "owner_type": owner_type,
        "owner_id": owner_id,
        "grafana_uid": definition["uid"],
        "slug": definition["slug"],
        "embed_url": embed_url,
        "view_url": view_url,
        "edit_url": edit_url,
        "variables": variables or {},
        "tags": tags or [],
        "context": context or {},
        "height": int(definition.get("height", 720)),
    }


def append_time_conditions(conditions: list[str], params: list[Any], column: str, from_ts=None, to_ts=None):
    if from_ts is not None:
        conditions.append(f"{column} >= %s")
        params.append(from_ts)

    if to_ts is not None:
        conditions.append(f"{column} <= %s")
        params.append(to_ts)


def append_text_search(conditions: list[str], params: list[Any], q: Optional[str], expressions: list[str]):
    normalized = str(q or "").strip()
    if not normalized:
        return

    search_value = f"%{normalized.lower()}%"
    like_parts = [f"LOWER(COALESCE({expr}, '')) LIKE %s" for expr in expressions]
    conditions.append("(" + " OR ".join(like_parts) + ")")
    params.extend([search_value] * len(expressions))


def unique_text_items(values: Any) -> list[str]:
    seen: set[str] = set()
    items: list[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        items.append(text)
    return items


def normalize_incident_signal_contexts(signal_contexts: Any) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_item in signal_contexts or []:
        item = raw_item if isinstance(raw_item, dict) else {}
        signal = str(item.get("signal") or "").strip()
        focus = str(item.get("focus") or "host").strip() or "host"
        label = str(item.get("label") or signal or "Sinal").strip()
        key = (signal, focus)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = {
                "signal": signal,
                "label": label,
                "focus": focus,
                "interfaces": [],
                "count": 0,
                "first_seen_at": item.get("first_seen_at"),
                "last_seen_at": item.get("last_seen_at"),
            }
            buckets[key] = bucket

        bucket["count"] += max(1, int(item.get("count") or 0))
        bucket["interfaces"] = unique_text_items([*bucket["interfaces"], *(item.get("interfaces") or [])])

        first_seen = item.get("first_seen_at")
        last_seen = item.get("last_seen_at")
        if first_seen and (not bucket["first_seen_at"] or str(first_seen) < str(bucket["first_seen_at"])):
            bucket["first_seen_at"] = first_seen
        if last_seen and (not bucket["last_seen_at"] or str(last_seen) > str(bucket["last_seen_at"])):
            bucket["last_seen_at"] = last_seen

    return sorted(
        buckets.values(),
        key=lambda item: (-int(item.get("count") or 0), str(item.get("signal") or ""), str(item.get("focus") or "")),
    )


def normalize_incident_details(details: Any) -> dict[str, Any]:
    payload = details if isinstance(details, dict) else {}
    normalized = dict(payload)
    signal_contexts = normalize_incident_signal_contexts(payload.get("signal_contexts"))
    affected_contexts = unique_text_items(payload.get("affected_contexts"))
    if not affected_contexts and signal_contexts:
        affected_contexts = unique_text_items(
            item.get("focus")
            for item in signal_contexts
            if str(item.get("focus") or "").strip() not in ("", "host", "unknown")
        )

    normalized["signal_contexts"] = signal_contexts
    normalized["affected_contexts"] = affected_contexts
    normalized["opening_reason"] = str(payload.get("opening_reason") or "").strip() or None
    normalized["evidences"] = unique_text_items(payload.get("evidences") or payload.get("evidence") or [])
    return normalized


def incident_output_from_row(row) -> dict[str, Any]:
    return {
        "id": row[0],
        "opened_at": to_iso(row[1]) or "",
        "last_seen_at": to_iso(row[2]) or "",
        "status": normalize_status_value(row[3]) or "",
        "hostname": row[4],
        "src_ip": str(row[5]),
        "incident_type": row[6],
        "key": row[7],
        "severity": normalize_severity_value(row[8]) or "",
        "title": row[9],
        "details": normalize_incident_details(row[10]),
        "asset_id": row[11],
        "group_id": row[12],
        "group_name": row[13],
        "group_path": row[14],
        "template_id": row[15],
        "template_name": row[16],
    }


def syslog_output_from_row(row) -> dict[str, Any]:
    resolved = enrich_syslog_event_fields(
        process=row[10],
        severity=row[13],
        subsystem=row[14],
        iface=row[16],
        message=row[17],
        raw=row[18],
    )
    return {
        "id": row[0],
        "ts": to_iso(row[1]) or "",
        "hostname": row[2],
        "src_ip": str(row[3]),
        "asset_id": row[4],
        "group_id": row[5],
        "group_name": row[6],
        "group_path": row[7],
        "template_id": row[8],
        "template_name": row[9],
        "process": row[10],
        "pid": row[11],
        "event_id": row[12],
        "severity": resolved["severity"],
        "subsystem": resolved["subsystem"],
        "slot": row[15],
        "iface": resolved["iface"],
        "message": row[17],
        "raw": row[18],
    }


def attach_host_operational_state(cur, hosts: list[dict[str, Any]], from_ts=None, to_ts=None) -> list[dict[str, Any]]:
    if not hosts:
        return hosts

    host_ids = [int(host["id"]) for host in hosts]
    by_host_id = {int(host["id"]): host for host in hosts}

    metrics_conditions = ["asset_id = ANY(%s)"]
    metrics_params: list[Any] = [host_ids]
    append_time_conditions(metrics_conditions, metrics_params, "ts", from_ts, to_ts)
    metrics_where = " WHERE " + " AND ".join(metrics_conditions)

    cur.execute(
        f"""
        SELECT DISTINCT ON (asset_id) asset_id, ts
        FROM metrics
        {metrics_where}
        ORDER BY asset_id, ts DESC
        """,
        metrics_params,
    )
    for asset_id, ts in cur.fetchall():
        by_host_id[int(asset_id)]["last_collection_at"] = to_iso(ts)

    alive_conditions = list(metrics_conditions)
    alive_params = list(metrics_params)
    alive_conditions.append("metric = 'host.alive'")
    cur.execute(
        f"""
        SELECT DISTINCT ON (asset_id) asset_id, ts, value
        FROM metrics
        WHERE {" AND ".join(alive_conditions)}
        ORDER BY asset_id, ts DESC
        """,
        alive_params,
    )
    for asset_id, ts, value in cur.fetchall():
        host = by_host_id[int(asset_id)]
        host["_last_alive_ts"] = ts
        host["_last_alive_value"] = float(value) if value is not None else None
        host["last_icmp_collection_at"] = to_iso(ts)

    snmp_conditions = list(metrics_conditions)
    snmp_params = list(metrics_params)
    snmp_conditions.append("metric LIKE 'snmp.%%'")
    cur.execute(
        f"""
        SELECT DISTINCT ON (asset_id) asset_id, ts
        FROM metrics
        WHERE {" AND ".join(snmp_conditions)}
        ORDER BY asset_id, ts DESC
        """,
        snmp_params,
    )
    for asset_id, ts in cur.fetchall():
        by_host_id[int(asset_id)]["last_snmp_collection_at"] = to_iso(ts)

    incident_conditions = ["asset_id = ANY(%s)"]
    incident_params: list[Any] = [host_ids]
    append_time_conditions(incident_conditions, incident_params, "COALESCE(last_seen_at, opened_at)", from_ts, to_ts)
    cur.execute(
        f"""
        SELECT
            asset_id,
            COUNT(*) FILTER (WHERE LOWER(status) IN ('open','acknowledged')) AS open_incidents,
            MAX(COALESCE(last_seen_at, opened_at)) AS last_incident_at,
            (ARRAY_AGG(severity ORDER BY {severity_rank_sql('severity')} DESC,
                COALESCE(last_seen_at, opened_at) DESC NULLS LAST))[1] AS max_incident_severity,
            (ARRAY_AGG(title ORDER BY COALESCE(last_seen_at, opened_at) DESC NULLS LAST))[1] AS last_incident_title,
            COALESCE(
                JSONB_AGG(
                    JSONB_BUILD_OBJECT(
                        'id', id,
                        'incident_type', incident_type,
                        'problem_type', problem_type,
                        'severity', severity,
                        'title', title,
                        'status', status,
                        'last_seen_at', COALESCE(last_seen_at, opened_at)
                    )
                    ORDER BY {severity_rank_sql('severity')} DESC, COALESCE(last_seen_at, opened_at) DESC NULLS LAST
                ) FILTER (WHERE LOWER(status) IN ('open','acknowledged')),
                '[]'::jsonb
            ) AS open_incident_items
        FROM incidents
        WHERE {" AND ".join(incident_conditions)}
        GROUP BY asset_id
        """,
        incident_params,
    )
    for asset_id, open_incidents, last_incident_at, max_severity, last_title, open_items in cur.fetchall():
        host = by_host_id[int(asset_id)]
        host["open_incidents"] = int(open_incidents or 0)
        host["last_incident_at"] = to_iso(last_incident_at)
        host["last_incident_title"] = last_title
        host["max_incident_severity"] = normalize_severity_value(max_severity)
        host["_open_incident_items"] = open_items or []

    syslog_conditions = ["asset_id = ANY(%s)"]
    syslog_params: list[Any] = [host_ids]
    append_time_conditions(syslog_conditions, syslog_params, "ts", from_ts, to_ts)
    cur.execute(
        f"""
        SELECT asset_id, MAX(ts) AS last_syslog_at
        FROM syslog_events
        WHERE {" AND ".join(syslog_conditions)}
        GROUP BY asset_id
        """,
        syslog_params,
    )
    for asset_id, last_syslog_at in cur.fetchall():
        by_host_id[int(asset_id)]["_last_syslog_at"] = last_syslog_at

    anomaly_conditions = ["asset_id = ANY(%s)"]
    anomaly_params: list[Any] = [host_ids]
    append_time_conditions(anomaly_conditions, anomaly_params, "ts", from_ts, to_ts)
    cur.execute(
        f"""
        SELECT asset_id, MAX(ts) AS last_prediction_at
        FROM anomaly_scores
        WHERE {" AND ".join(anomaly_conditions)}
        GROUP BY asset_id
        """,
        anomaly_params,
    )
    for asset_id, last_prediction_at in cur.fetchall():
        by_host_id[int(asset_id)]["_last_prediction_at"] = last_prediction_at

    loop_conditions = list(anomaly_conditions)
    loop_params = list(anomaly_params)
    loop_conditions.append("metric = 'loop_risk'")
    cur.execute(
        f"""
        SELECT DISTINCT ON (asset_id) asset_id, ts, score
        FROM anomaly_scores
        WHERE {" AND ".join(loop_conditions)}
        ORDER BY asset_id, ts DESC
        """,
        loop_params,
    )
    for asset_id, loop_ts, score in cur.fetchall():
        host = by_host_id[int(asset_id)]
        host["loop_risk_score"] = float(score) if score is not None else None
        host["loop_risk_ts"] = to_iso(loop_ts)

    for host in hosts:
        resolved_policy = normalize_collection_policy(host.get("collection_policy_resolved") or {})
        now_utc = datetime.now(timezone.utc)
        last_icmp_at = parse_datetime_filter(host.get("last_icmp_collection_at")) if host.get("last_icmp_collection_at") else None
        last_snmp_at = parse_datetime_filter(host.get("last_snmp_collection_at")) if host.get("last_snmp_collection_at") else None
        icmp_interval = int(resolved_policy.get("icmp_interval_sec") or 60)
        snmp_interval = int(resolved_policy.get("snmp_interval_sec") or 60)
        icmp_current_ok = (
            host.get("_last_alive_value") is not None
            and float(host.get("_last_alive_value") or 0) >= 1
            and last_icmp_at is not None
            and (now_utc - last_icmp_at).total_seconds() <= max(60, icmp_interval * 4)
        )
        snmp_current_ok = (
            last_snmp_at is not None
            and (now_utc - last_snmp_at).total_seconds() <= max(180, snmp_interval * 4)
        )
        last_loop_at = parse_datetime_filter(host.get("loop_risk_ts")) if host.get("loop_risk_ts") else None
        loop_current_window_sec = max(
            180,
            LOOP_RISK_WINDOW_SEC + max(0, LOOP_RISK_CLEAN_CYCLES - 1) * DEFAULT_ICMP_INTERVAL_SEC,
        )
        loop_current_active = (
            last_loop_at is not None
            and (now_utc - last_loop_at).total_seconds() <= loop_current_window_sec
            and float(host.get("loop_risk_score") or 0) >= LOOP_RISK_OPEN_SCORE
        )
        snmp_expected_current = bool(host.get("snmp_profile") or last_snmp_at)
        if not snmp_expected_current:
            open_kinds = {
                str(item.get("problem_type") or item.get("incident_type") or "").strip().lower()
                for item in (host.get("_open_incident_items") or [])
            }
            snmp_expected_current = "snmp_collection_silence" in open_kinds
        health_status, health_reason = host_health_status(
            bool(host["enabled"]),
            host.get("_last_alive_value"),
            parse_datetime_filter(host.get("last_collection_at")) if host.get("last_collection_at") else None,
            host.get("_open_incident_items") or [],
            icmp_current_ok=icmp_current_ok,
            snmp_current_ok=snmp_current_ok,
            snmp_expected_current=snmp_expected_current,
            loop_current_active=loop_current_active,
        )
        host["health_status"] = health_status
        host["health_reason"] = health_reason
        last_activity_at = latest_timestamp(
            parse_datetime_filter(host.get("last_collection_at")) if host.get("last_collection_at") else None,
            parse_datetime_filter(host.get("last_incident_at")) if host.get("last_incident_at") else None,
            host.get("_last_syslog_at"),
            host.get("_last_prediction_at"),
        )
        host["last_activity_at"] = to_iso(last_activity_at)
        host["next_icmp_collection_at"] = add_seconds_to_iso(
            host.get("last_icmp_collection_at"),
            resolved_policy.get("icmp_interval_sec"),
        )
        host["next_snmp_collection_at"] = add_seconds_to_iso(
            host.get("last_snmp_collection_at"),
            resolved_policy.get("snmp_interval_sec"),
        )
        host.pop("_last_alive_ts", None)
        host.pop("_last_alive_value", None)
        host.pop("_last_syslog_at", None)
        host.pop("_last_prediction_at", None)
        host.pop("_template_definition", None)
        host.pop("_open_incident_items", None)

    return hosts


def select_incident_records(
    cur,
    *,
    asset_id: Optional[int] = None,
    host_record: Optional[dict[str, Any]] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    q: Optional[str] = None,
    from_ts=None,
    to_ts=None,
    limit: int = 200,
    active_hosts_only: bool = False,
):
    query = """
        SELECT
            i.id,
            i.opened_at,
            i.last_seen_at,
            i.status,
            i.hostname,
            i.src_ip,
            i.incident_type,
            i.key,
            i.severity,
            i.title,
            i.details,
            i.asset_id,
            a.group_id,
            g.name,
            g.path,
            a.template_id,
            t.name
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.asset_id
        LEFT JOIN host_groups g ON g.id = a.group_id
        LEFT JOIN monitoring_templates t ON t.id = a.template_id
    """
    conditions: list[str] = []
    params: list[Any] = []

    if active_hosts_only:
        conditions.append("COALESCE(a.enabled, TRUE) = TRUE")

    if asset_id is not None:
        conditions.append("i.asset_id = %s")
        params.append(asset_id)
    elif host_record is not None:
        conditions.append(
            "(i.asset_id = %s OR (i.asset_id IS NULL AND (i.src_ip = %s::inet OR LOWER(i.hostname) = LOWER(%s))))"
        )
        params.extend([host_record["id"], host_record["ip"], host_record["name"]])

    if group_id is not None:
        conditions.append("a.group_id = %s")
        params.append(group_id)

    if template_id is not None:
        conditions.append("a.template_id = %s")
        params.append(template_id)

    normalized_status = normalize_status_value(status)
    if normalized_status:
        conditions.append("LOWER(i.status) = %s")
        params.append(normalized_status)

    normalized_severity = normalize_severity_value(severity)
    if normalized_severity:
        conditions.append("LOWER(i.severity) = %s")
        params.append(normalized_severity)

    if incident_type:
        conditions.append("LOWER(i.incident_type) = %s")
        params.append(str(incident_type).strip().lower())

    append_time_conditions(conditions, params, "COALESCE(i.last_seen_at, i.opened_at)", from_ts, to_ts)
    append_text_search(
        conditions,
        params,
        q,
        [
            "i.hostname",
            "i.src_ip::text",
            "i.incident_type",
            "i.title",
            "i.details->>'recommendation'",
        ],
    )

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += f"""
        ORDER BY {severity_rank_sql('i.severity')} DESC,
                 COALESCE(i.last_seen_at, i.opened_at) DESC,
                 i.id DESC
        LIMIT %s
    """
    params.append(normalize_limit(limit, default=200, maximum=2000))
    cur.execute(query, params)
    return [incident_output_from_row(row) for row in cur.fetchall()]


def resolve_open_incidents_for_disabled_host(
    cur,
    host_id: int,
    *,
    host_name: Optional[str] = None,
    host_ip: Optional[str] = None,
) -> list[int]:
    recovery_evidence = f"Host {host_name or host_id} ({host_ip or '-'}) foi desativado no NetGuard."
    details_patch = {
        "recovery_source": "host_disabled",
        "recovery_value": "Host desativado no cadastro; monitoramento pausado.",
        "recovery_evidence": recovery_evidence,
    }
    cur.execute(
        """
        UPDATE incidents
        SET status = 'resolved',
            resolved_at = COALESCE(resolved_at, NOW()),
            last_seen_at = COALESCE(last_seen_at, NOW()),
            updated_at = NOW(),
            details = COALESCE(details, '{}'::jsonb) || %s::jsonb
        WHERE asset_id = %s
          AND LOWER(COALESCE(status, '')) IN ('open', 'acknowledged')
        RETURNING id
        """,
        (json.dumps(details_patch, ensure_ascii=False), host_id),
    )
    return [int(row[0]) for row in cur.fetchall()]


def select_syslog_records(
    cur,
    *,
    asset_id: Optional[int] = None,
    host_record: Optional[dict[str, Any]] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    severity: Optional[str] = None,
    subsystem: Optional[str] = None,
    q: Optional[str] = None,
    from_ts=None,
    to_ts=None,
    limit: int = 100,
):
    query = """
        SELECT
            s.id,
            s.ts,
            s.hostname,
            s.src_ip,
            s.asset_id,
            a.group_id,
            g.name,
            g.path,
            a.template_id,
            t.name,
            s.process,
            s.pid,
            s.event_id,
            s.severity,
            s.subsystem,
            s.slot,
            s.iface,
            s.message,
            s.raw
        FROM syslog_events s
        LEFT JOIN assets a ON a.id = s.asset_id
        LEFT JOIN host_groups g ON g.id = a.group_id
        LEFT JOIN monitoring_templates t ON t.id = a.template_id
    """
    conditions: list[str] = []
    params: list[Any] = []

    if asset_id is not None:
        conditions.append("s.asset_id = %s")
        params.append(asset_id)
    elif host_record is not None:
        conditions.append(
            "(s.asset_id = %s OR (s.asset_id IS NULL AND (s.src_ip = %s::inet OR LOWER(s.hostname) = LOWER(%s))))"
        )
        params.extend([host_record["id"], host_record["ip"], host_record["name"]])

    if group_id is not None:
        conditions.append("a.group_id = %s")
        params.append(group_id)

    if template_id is not None:
        conditions.append("a.template_id = %s")
        params.append(template_id)

    normalized_severity = normalize_severity_value(severity)
    if normalized_severity:
        conditions.append("LOWER(COALESCE(s.severity, '')) = %s")
        params.append(normalized_severity)

    if subsystem:
        conditions.append("LOWER(COALESCE(s.subsystem, '')) = %s")
        params.append(str(subsystem).strip().lower())

    append_time_conditions(conditions, params, "s.ts", from_ts, to_ts)
    append_text_search(
        conditions,
        params,
        q,
        [
            "s.hostname",
            "s.src_ip::text",
            "s.subsystem",
            "s.iface",
            "s.message",
            "s.raw",
        ],
    )

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY s.ts DESC, s.id DESC LIMIT %s"
    params.append(normalize_limit(limit, default=100, maximum=2000))
    cur.execute(query, params)
    return [syslog_output_from_row(row) for row in cur.fetchall()]


def select_prediction_records(
    cur,
    *,
    asset_id: Optional[int] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    metric: Optional[str] = None,
    q: Optional[str] = None,
    from_ts=None,
    to_ts=None,
    limit: int = 100,
):
    query = """
        SELECT
            s.ts,
            s.asset_id,
            a.name,
            a.ip,
            a.group_id,
            g.name,
            g.path,
            a.template_id,
            t.name,
            s.metric,
            s.key,
            s.score,
            s.z,
            s.value,
            s.baseline_mean,
            s.baseline_std,
            s.details
        FROM anomaly_scores s
        JOIN assets a ON a.id = s.asset_id
        LEFT JOIN host_groups g ON g.id = a.group_id
        LEFT JOIN monitoring_templates t ON t.id = a.template_id
    """
    conditions: list[str] = []
    params: list[Any] = []

    if asset_id is not None:
        conditions.append("s.asset_id = %s")
        params.append(asset_id)

    if group_id is not None:
        conditions.append("a.group_id = %s")
        params.append(group_id)

    if template_id is not None:
        conditions.append("a.template_id = %s")
        params.append(template_id)

    if metric:
        conditions.append("LOWER(s.metric) = %s")
        params.append(str(metric).strip().lower())

    append_time_conditions(conditions, params, "s.ts", from_ts, to_ts)
    append_text_search(
        conditions,
        params,
        q,
        [
            "a.name",
            "a.ip::text",
            "s.metric",
            "s.key",
            "s.details->>'ifName'",
            "s.details->>'recommendation'",
        ],
    )

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY s.ts DESC, s.asset_id, s.metric LIMIT %s"
    params.append(normalize_limit(limit, default=100, maximum=2000))
    cur.execute(query, params)
    rows = cur.fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        score_value = float(row[11]) if row[11] is not None else 0.0
        results.append(
            {
                "ts": to_iso(row[0]) or "",
                "asset_id": row[1],
                "hostname": row[2],
                "src_ip": str(row[3]),
                "group_id": row[4],
                "group_name": row[5],
                "group_path": row[6],
                "template_id": row[7],
                "template_name": row[8],
                "metric": row[9],
                "key": row[10],
                "score": score_value,
                "severity": prediction_severity(score_value),
                "z": float(row[12]) if row[12] is not None else None,
                "value": float(row[13]) if row[13] is not None else None,
                "baseline_mean": float(row[14]) if row[14] is not None else None,
                "baseline_std": float(row[15]) if row[15] is not None else None,
                "details": row[16] or {},
            }
        )

    return results


REPORT_SYSLOG_KEYWORDS = (
    "loop",
    "stp",
    "topology",
    "flapping",
    "broadcast",
    "storm",
    "discard",
    "error",
    "down",
    "instab",
)


def report_source_label(source: Optional[str]) -> str:
    labels = {
        "incident": "Incidente",
        "syslog": "Syslog",
        "prediction": "Previsão",
    }
    return labels.get(normalize_status_value(source) or "", "Evento")


def shorten_report_text(value: Optional[str], limit: int = 220) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return "-"
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def extract_prediction_iface_name(item: dict[str, Any]) -> Optional[str]:
    details = item.get("details") or {}
    iface = details.get("ifName")
    if iface:
        return str(iface)

    key = str(item.get("key") or "")
    if "=" in key:
        return key.split("=", 1)[1]
    return None


def format_prediction_report_title(item: dict[str, Any]) -> str:
    metric = str(item.get("metric") or "")
    iface = extract_prediction_iface_name(item)

    if metric.lower() == "loop_risk":
        return "Predição de risco de loop"
    if iface:
        return f"Anomalia em {iface}"
    if metric:
        return f"Anomalia em {metric}"
    return "Anomalia detectada"


def format_prediction_report_details(item: dict[str, Any]) -> str:
    details = item.get("details") or {}
    recommendation = details.get("recommendation")
    if recommendation:
        return shorten_report_text(str(recommendation))

    parts: list[str] = []
    score_pct = int(round(float(item.get("score") or 0) * 100))
    parts.append(f"Score {score_pct}%")

    iface = extract_prediction_iface_name(item)
    if iface:
        parts.append(str(iface))

    if item.get("value") is not None:
        parts.append(f"valor {float(item.get('value')):.2f}")

    return shorten_report_text(" • ".join(parts))


def format_incident_report_details(item: dict[str, Any]) -> str:
    details = item.get("details") or {}
    recommendation = details.get("recommendation")
    evidences = details.get("evidences") or details.get("evidence")

    parts: list[str] = []
    if recommendation:
        parts.append(str(recommendation))

    if isinstance(evidences, list) and evidences:
        parts.append("Evidências: " + ", ".join(str(value) for value in evidences[:3]))

    if not parts and item.get("incident_type"):
        parts.append(str(item["incident_type"]).replace("_", " "))

    return shorten_report_text(" ".join(parts))


def format_syslog_report_details(item: dict[str, Any]) -> str:
    parts: list[str] = []
    if item.get("subsystem"):
        parts.append(str(item["subsystem"]))
    if item.get("iface"):
        parts.append(str(item["iface"]))
    if item.get("src_ip"):
        parts.append(str(item["src_ip"]))

    raw_text = item.get("raw") or item.get("message") or ""
    if raw_text:
        parts.append(str(raw_text))

    return shorten_report_text(" • ".join(parts))


def is_relevant_syslog_record(item: dict[str, Any], q: Optional[str] = None) -> bool:
    if q:
        return True

    severity = normalize_severity_value(item.get("severity"))
    if severity in {"critical", "high", "warning", "notice"}:
        return True

    haystack = " ".join(
        [
            str(item.get("subsystem") or ""),
            str(item.get("iface") or ""),
            str(item.get("message") or ""),
            str(item.get("raw") or ""),
        ]
    ).lower()
    return any(term in haystack for term in REPORT_SYSLOG_KEYWORDS)


def build_report_event_records(
    cur,
    *,
    asset_id: Optional[int] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    from_ts=None,
    to_ts=None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    normalized_source = normalize_status_value(source)
    normalized_severity = normalize_severity_value(severity)
    normalized_limit = normalize_limit(limit, default=200, maximum=2000)
    fetch_limit = min(max(normalized_limit * 3, 300), 2000)

    records: list[dict[str, Any]] = []

    if normalized_source in (None, "all", "incident"):
        incident_records = select_incident_records(
            cur,
            asset_id=asset_id,
            group_id=group_id,
            template_id=template_id,
            severity=normalized_severity,
            q=q,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=fetch_limit,
        )
        for item in incident_records:
            records.append(
                {
                    "id": f"incident-{item['id']}",
                    "ts": item["last_seen_at"] or item["opened_at"],
                    "severity": normalize_severity_value(item.get("severity")) or "info",
                    "source": "incident",
                    "source_label": report_source_label("incident"),
                    "host_name": item.get("hostname"),
                    "host_ip": item.get("src_ip"),
                    "context_name": item.get("hostname"),
                    "group_name": item.get("group_name"),
                    "template_name": item.get("template_name"),
                    "title": shorten_report_text(item.get("title"), 120),
                    "details": format_incident_report_details(item),
                    "status": normalize_status_value(item.get("status")),
                    "signal_type": normalize_status_value(item.get("incident_type")) or "incident",
                    "asset_id": item.get("asset_id"),
                    "group_id": item.get("group_id"),
                    "template_id": item.get("template_id"),
                }
            )

    if normalized_source in (None, "all", "syslog"):
        syslog_records = select_syslog_records(
            cur,
            asset_id=asset_id,
            group_id=group_id,
            template_id=template_id,
            severity=normalized_severity,
            q=q,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=fetch_limit,
        )
        for item in syslog_records:
            if not is_relevant_syslog_record(item, q=q):
                continue

            context_name = item.get("hostname")
            if item.get("iface"):
                context_name = f"{context_name} • {item['iface']}" if context_name else item["iface"]

            records.append(
                {
                    "id": f"syslog-{item['id']}",
                    "ts": item["ts"],
                    "severity": normalize_severity_value(item.get("severity")) or "info",
                    "source": "syslog",
                    "source_label": report_source_label("syslog"),
                    "host_name": item.get("hostname"),
                    "host_ip": item.get("src_ip"),
                    "context_name": context_name,
                    "group_name": item.get("group_name"),
                    "template_name": item.get("template_name"),
                    "title": shorten_report_text(item.get("message"), 120),
                    "details": format_syslog_report_details(item),
                    "status": None,
                    "signal_type": normalize_status_value(item.get("subsystem")) or "syslog",
                    "asset_id": item.get("asset_id"),
                    "group_id": item.get("group_id"),
                    "template_id": item.get("template_id"),
                }
            )

    if normalized_source in (None, "all", "prediction"):
        prediction_records = select_prediction_records(
            cur,
            asset_id=asset_id,
            group_id=group_id,
            template_id=template_id,
            q=q,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=fetch_limit,
        )
        for item in prediction_records:
            severity_value = normalize_severity_value(item.get("severity")) or "info"
            if normalized_severity and severity_value != normalized_severity:
                continue
            if not q and severity_rank(severity_value) < severity_rank("medium"):
                continue

            iface = extract_prediction_iface_name(item)
            context_name = item.get("hostname")
            if iface:
                context_name = f"{context_name} • {iface}" if context_name else iface

            records.append(
                {
                    "id": f"prediction-{item['asset_id']}-{item['metric']}-{item['ts']}",
                    "ts": item["ts"],
                    "severity": severity_value,
                    "source": "prediction",
                    "source_label": report_source_label("prediction"),
                    "host_name": item.get("hostname"),
                    "host_ip": item.get("src_ip"),
                    "context_name": context_name,
                    "group_name": item.get("group_name"),
                    "template_name": item.get("template_name"),
                    "title": shorten_report_text(format_prediction_report_title(item), 120),
                    "details": format_prediction_report_details(item),
                    "status": None,
                    "signal_type": normalize_status_value(item.get("metric")) or "prediction",
                    "asset_id": item.get("asset_id"),
                    "group_id": item.get("group_id"),
                    "template_id": item.get("template_id"),
                }
            )

    records.sort(
        key=lambda item: (
            item.get("ts") or "",
            severity_rank(item.get("severity")),
        ),
        reverse=True,
    )
    return records[:normalized_limit]

def snmpwalk_lines(ip: str, community: str, oid: str, version: str = "2c") -> list[str]:
    cmd = [
        "snmpwalk",
        f"-v{version}",
        "-c",
        community,
        ip,
        oid,
    ]

    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=20)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=400, detail=f"SNMP walk failed: {e.output.strip()}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=400, detail="SNMP walk timeout")

    return [line.strip() for line in out.splitlines() if line.strip()]


def safe_snmpwalk_lines(ip: str, community: str, oid: str, version: str = "2c") -> list[str]:
    try:
        return snmpwalk_lines(ip, community, oid, version)
    except HTTPException:
        return []


def parse_snmp_indexed_values(lines: list[str]) -> dict[int, str]:
    """
    Exemplo de linha:
    iso.3.6.1.2.1.2.2.1.2.6 = STRING: "1/1/6"
    iso.3.6.1.2.1.2.2.1.8.6 = INTEGER: 1
    """
    result: dict[int, str] = {}

    for line in lines:
        m = re.match(r"^.*\.([0-9]+)\s*=\s*[^:]+:\s*(.*)$", line)
        if not m:
            continue

        idx = int(m.group(1))
        raw_value = m.group(2).strip()

        if raw_value.startswith('"') and raw_value.endswith('"'):
            raw_value = raw_value[1:-1]

        result[idx] = raw_value

    return result


def should_select_interface(ifdescr: str, admin_status: Optional[int] = None, oper_status: Optional[int] = None) -> bool:
    name = (ifdescr or "").strip().lower()

    # interfaces claramente internas/irrelevantes
    excluded_exact = {"lo", "loopback", "null0"}
    if name in excluded_exact:
        return False

    # vlan 1 geralmente é default e pouco útil
    if name == "vlan1":
        return False

    # se estiver administrativamente down, não selecionar por padrão
    if admin_status != 1:
        return False

    # qualquer interface administrativamente up pode ser monitorada
    return True


DISCOVERED_INTERFACE_SELECT = """
    id,
    asset_id,
    ifindex,
    ifdescr,
    if_name,
    if_alias,
    admin_status,
    oper_status,
    last_seen_at,
    last_change,
    speed_bps,
    mac_address,
    last_in_octets,
    last_out_octets,
    last_in_errors,
    last_out_errors,
    last_in_discards,
    last_out_discards,
    last_in_bps,
    last_out_bps,
    last_error,
    selected
"""


def discovered_interface_row_to_dict(row) -> dict[str, Any]:
    return {
        "id": row[0],
        "asset_id": row[1],
        "ifindex": row[2],
        "ifdescr": row[3],
        "if_name": row[4],
        "if_alias": row[5],
        "admin_status": row[6],
        "oper_status": row[7],
        "last_seen_at": to_iso(row[8]),
        "last_change": to_iso(row[9]),
        "speed_bps": row[10],
        "mac_address": row[11],
        "last_in_octets": float(row[12]) if row[12] is not None else None,
        "last_out_octets": float(row[13]) if row[13] is not None else None,
        "last_in_errors": float(row[14]) if row[14] is not None else None,
        "last_out_errors": float(row[15]) if row[15] is not None else None,
        "last_in_discards": float(row[16]) if row[16] is not None else None,
        "last_out_discards": float(row[17]) if row[17] is not None else None,
        "last_in_bps": float(row[18]) if row[18] is not None else None,
        "last_out_bps": float(row[19]) if row[19] is not None else None,
        "last_error": row[20],
        "selected": bool(row[21]),
    }


def list_discovered_interface_rows(cur, asset_id: int):
    cur.execute(
        f"""
        SELECT {DISCOVERED_INTERFACE_SELECT}
        FROM discovered_interfaces
        WHERE asset_id = %s
        ORDER BY ifindex
        """,
        (asset_id,)
    )
    return cur.fetchall()


def discover_interfaces_for_asset(cur, asset_id: int, ip: str, snmp_profile: dict[str, Any]):
    version = "2c"
    if str(snmp_profile.get("version", "v2c")).lower() == "v1":
        version = "1"

    community = snmp_profile.get("community")
    if not community:
        raise HTTPException(status_code=400, detail="Host has no SNMP community configured")

    ifdescr_lines = snmpwalk_lines(ip, community, "1.3.6.1.2.1.2.2.1.2", version)
    ifname_lines = safe_snmpwalk_lines(ip, community, "1.3.6.1.2.1.31.1.1.1.1", version)
    ifalias_lines = safe_snmpwalk_lines(ip, community, "1.3.6.1.2.1.31.1.1.1.18", version)
    admin_lines = snmpwalk_lines(ip, community, "1.3.6.1.2.1.2.2.1.7", version)
    oper_lines = snmpwalk_lines(ip, community, "1.3.6.1.2.1.2.2.1.8", version)
    speed_lines = safe_snmpwalk_lines(ip, community, "1.3.6.1.2.1.2.2.1.5", version)
    highspeed_lines = safe_snmpwalk_lines(ip, community, "1.3.6.1.2.1.31.1.1.1.15", version)
    mac_lines = safe_snmpwalk_lines(ip, community, "1.3.6.1.2.1.2.2.1.6", version)

    ifdescr_map = parse_snmp_indexed_values(ifdescr_lines)
    ifname_map = parse_snmp_indexed_values(ifname_lines)
    ifalias_map = parse_snmp_indexed_values(ifalias_lines)
    admin_map = parse_snmp_indexed_values(admin_lines)
    oper_map = parse_snmp_indexed_values(oper_lines)
    speed_map = parse_snmp_indexed_values(speed_lines)
    highspeed_map = parse_snmp_indexed_values(highspeed_lines)
    mac_map = parse_snmp_indexed_values(mac_lines)

    for ifindex, ifdescr in ifdescr_map.items():
        admin_status = int(admin_map[ifindex]) if ifindex in admin_map and str(admin_map[ifindex]).isdigit() else None
        oper_status = int(oper_map[ifindex]) if ifindex in oper_map and str(oper_map[ifindex]).isdigit() else None
        selected = should_select_interface(ifdescr, admin_status, oper_status)
        highspeed_mbps = int(highspeed_map[ifindex]) if ifindex in highspeed_map and str(highspeed_map[ifindex]).isdigit() else None
        speed_bps = highspeed_mbps * 1000000 if highspeed_mbps else (
            int(speed_map[ifindex]) if ifindex in speed_map and str(speed_map[ifindex]).isdigit() else None
        )

        cur.execute(
            """
            INSERT INTO discovered_interfaces
                (asset_id, ifindex, ifdescr, if_name, if_alias, admin_status, oper_status,
                 speed_bps, mac_address, selected, last_seen_at, updated_at)
            VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now())
            ON CONFLICT (asset_id, ifindex)
            DO UPDATE SET
                ifdescr = EXCLUDED.ifdescr,
                if_name = EXCLUDED.if_name,
                if_alias = EXCLUDED.if_alias,
                admin_status = EXCLUDED.admin_status,
                oper_status = EXCLUDED.oper_status,
                speed_bps = EXCLUDED.speed_bps,
                mac_address = EXCLUDED.mac_address,
                selected = discovered_interfaces.selected OR EXCLUDED.selected,
                last_seen_at = now(),
                updated_at = now()
            """,
            (
                asset_id,
                ifindex,
                ifdescr,
                ifname_map.get(ifindex),
                ifalias_map.get(ifindex),
                admin_status,
                oper_status,
                speed_bps,
                mac_map.get(ifindex),
                selected,
            )
        )

    return list_discovered_interface_rows(cur, asset_id)


def find_host_by_name_or_ip(cur, host_name: str, host_ip: str):
    normalized_ip = (host_ip or "").strip()
    normalized_name = (host_name or "").strip()

    cur.execute(
        f"""
        SELECT id, name, ip, snmp_profile, tags, enabled
        FROM {ASSETS_TABLE}
        WHERE ip::text = %s
           OR LOWER(name) = LOWER(%s)
        ORDER BY
            CASE WHEN ip::text = %s THEN 0 ELSE 1 END,
            CASE WHEN LOWER(name) = LOWER(%s) THEN 0 ELSE 1 END,
            id
        LIMIT 1
        """,
        (normalized_ip, normalized_name, normalized_ip, normalized_name),
    )
    row = cur.fetchone()

    if row is None:
        return None

    return {
        "id": row[0],
        "name": row[1],
        "ip": str(row[2]),
        "snmp_profile": row[3] or {},
        "tags": row[4] or {},
        "enabled": bool(row[5]),
    }


def resolve_profile_ids(cur, profile_names: tuple[str, ...]) -> dict[str, int]:
    wanted = {name.lower() for name in profile_names}

    cur.execute(
        """
        SELECT id, name
        FROM monitoring_profiles
        WHERE enabled = true
        ORDER BY id
        """
    )
    rows = cur.fetchall()

    resolved: dict[str, int] = {}
    for row in rows:
        profile_name = str(row[1]).lower()
        if profile_name in wanted:
            resolved[profile_name] = row[0]

    missing = [name for name in profile_names if name.lower() not in resolved]
    if missing:
        raise HTTPException(
            status_code=500,
            detail=f"Missing monitoring profiles for bootstrap: {', '.join(missing)}",
        )

    return resolved


def apply_host_profiles(cur, host_id: int, profile_ids: dict[str, int]):
    cur.execute("DELETE FROM asset_profiles WHERE asset_id = %s", (host_id,))

    for profile_name in DEMO_PROFILE_NAMES:
        cur.execute(
            """
            INSERT INTO asset_profiles (asset_id, profile_id, params, enabled)
            VALUES (%s, %s, %s, %s)
            """,
            (
                host_id,
                profile_ids[profile_name.lower()],
                psycopg.types.json.Json({}),
                True,
            )
        )


def select_interface_for_host(cur, asset_id: int, interface_name: str):
    cur.execute(
        """
        UPDATE discovered_interfaces
        SET selected = (LOWER(ifdescr) = LOWER(%s)),
            updated_at = now()
        WHERE asset_id = %s
        """,
        (interface_name, asset_id),
    )

    rows = list_discovered_interface_rows(cur, asset_id)
    if not any(str(row[3]).lower() == interface_name.lower() for row in rows):
        raise HTTPException(
            status_code=500,
            detail=f"Bootstrap could not find interface {interface_name} for host {asset_id}",
        )

    return rows


def bootstrap_lab_host_internal() -> LabBootstrapOut:
    with get_conn() as conn, conn.cursor() as cur:
        groups_ready = has_host_groups_schema(cur)
        templates_ready = has_monitoring_templates_schema(cur)
        lab_group_id = ensure_lab_group(cur) if groups_ready else None
        lab_template_id = get_template_id_by_slug(cur, DEMO_TEMPLATE_SLUG) if templates_ready else None
        lab_template = (
            get_monitoring_template_record(cur, lab_template_id)
            if lab_template_id is not None
            else None
        )
        current_host = find_host_by_name_or_ip(cur, DEMO_HOST_NAME, DEMO_HOST_IP)
        existing_tags = current_host["tags"] if current_host else {}

        host_tags = {
            **existing_tags,
            "demo_primary": True,
            "lab_host": True,
            "demo_role": "primary",
        }

        if current_host is None:
            insert_columns = ["name", "ip", "snmp_profile", "tags"]
            insert_values: list[Any] = [
                DEMO_HOST_NAME,
                DEMO_HOST_IP,
                psycopg.types.json.Json(DEMO_HOST_SNMP_PROFILE),
                psycopg.types.json.Json(host_tags),
            ]

            if groups_ready:
                insert_columns.append("group_id")
                insert_values.append(lab_group_id)

            if templates_ready:
                insert_columns.append("template_id")
                insert_values.append(lab_template_id)

            insert_columns.append("enabled")
            insert_values.append(True)

            cur.execute(
                f"""
                INSERT INTO {ASSETS_TABLE} ({', '.join(insert_columns)})
                VALUES ({', '.join(['%s'] * len(insert_values))})
                RETURNING id
                """,
                insert_values,
            )
            host_id = cur.fetchone()[0]
        else:
            host_id = current_host["id"]
            update_parts = [
                "name = %s",
                "ip = %s",
                "snmp_profile = %s",
                "tags = %s",
            ]
            update_values: list[Any] = [
                DEMO_HOST_NAME,
                DEMO_HOST_IP,
                psycopg.types.json.Json(DEMO_HOST_SNMP_PROFILE),
                psycopg.types.json.Json(host_tags),
            ]

            if groups_ready:
                update_parts.append("group_id = %s")
                update_values.append(lab_group_id)

            if templates_ready:
                update_parts.append("template_id = %s")
                update_values.append(lab_template_id)

            update_parts.append("enabled = %s")
            update_values.extend([True, host_id])

            cur.execute(
                f"""
                UPDATE {ASSETS_TABLE}
                SET {', '.join(update_parts)}
                WHERE id = %s
                """,
                update_values,
            )

        profile_ids = resolve_profile_ids(cur, DEMO_PROFILE_NAMES)
        apply_host_profiles(cur, host_id, profile_ids)

        discovered_rows = discover_interfaces_for_asset(
            cur,
            host_id,
            DEMO_HOST_IP,
            DEMO_HOST_SNMP_PROFILE,
        )
        select_interface_for_host(cur, host_id, DEMO_HOST_INTERFACE)
        conn.commit()

    return LabBootstrapOut(
        host_id=host_id,
        host_name=DEMO_HOST_NAME,
        host_ip=DEMO_HOST_IP,
        profiles_applied=["ICMP Basic", "Generic IF-MIB", "SNMP System"],
        selected_interface=DEMO_HOST_INTERFACE,
        interfaces_discovered=len(discovered_rows),
        template_name=lab_template["name"] if lab_template is not None else None,
    )

@app.get("/health")
def health():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return {"status": "ok", "database": "ok"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Banco de dados indisponivel para o healthcheck.") from exc


@app.get("/health/deep")
def health_deep():
    required_tables = {
        "assets",
        "metrics",
        "incidents",
        "incident_notifications",
        "alert_channels",
        "anomaly_scores",
        "syslog_events",
        "schema_migrations",
    }

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT now(), current_database()")
            checked_at, database = cur.fetchone()

            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = ANY(%s)
                """,
                (list(required_tables),),
            )
            existing_tables = {row[0] for row in cur.fetchall()}

            if "schema_migrations" in existing_tables:
                cur.execute(
                    """
                    SELECT version
                    FROM schema_migrations
                    ORDER BY version
                    """
                )
                migrations = [row[0] for row in cur.fetchall()]
            else:
                migrations = []
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Falha ao validar dependencias internas do NetGuard.") from exc

    missing_tables = sorted(required_tables - existing_tables)
    status = "ok" if not missing_tables else "degraded"
    return {
        "status": status,
        "database": "ok",
        "database_name": database,
        "checked_at": to_iso(checked_at),
        "missing_tables": missing_tables,
        "migrations": migrations,
    }


def housekeeper_runtime_settings() -> dict[str, Any]:
    def env_int(name: str, default: int) -> int:
        try:
            return int(float(os.environ.get(name, str(default))))
        except (TypeError, ValueError):
            return default

    return {
        "enabled": os.environ.get("HOUSEKEEPER_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on"),
        "interval_sec": env_int("HOUSEKEEPER_INTERVAL_SEC", 3600),
        "batch_rows": env_int("HOUSEKEEPER_BATCH_ROWS", 50000),
        "retention_days": {
            "metrics": env_int("RETENTION_METRICS_DAYS", 30),
            "syslog_events": env_int("RETENTION_SYSLOG_DAYS", 14),
            "anomaly_scores": env_int("RETENTION_ANOMALY_SCORES_DAYS", 30),
            "ai_insights": env_int("RETENTION_AI_INSIGHTS_DAYS", 30),
            "incident_notifications": env_int("RETENTION_NOTIFICATIONS_DAYS", 180),
            "resolved_incidents": env_int("RETENTION_RESOLVED_INCIDENTS_DAYS", 180),
        },
    }


@app.get("/housekeeper/status")
def housekeeper_status():
    settings = housekeeper_runtime_settings()
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("select to_regclass('housekeeper_runs')")
            exists = cur.fetchone()[0] is not None
            latest = None
            if exists:
                cur.execute(
                    """
                    select id, started_at, finished_at, status, settings, deleted, error
                    from housekeeper_runs
                    order by started_at desc, id desc
                    limit 1
                    """
                )
                row = cur.fetchone()
                if row:
                    latest = {
                        "id": row[0],
                        "started_at": to_iso(row[1]),
                        "finished_at": to_iso(row[2]),
                        "status": row[3],
                        "settings": row[4] or {},
                        "deleted": row[5] or {},
                        "error": row[6],
                    }
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Falha ao consultar status do housekeeper.") from exc

    return {
        "status": "ok" if latest is not None else "waiting_first_run",
        "settings": settings,
        "latest_run": latest,
    }


@app.get("/host-groups", response_model=List[HostGroupOut])
def list_host_groups():
    with get_conn() as conn, conn.cursor() as cur:
        if not has_host_groups_schema(cur):
            return []

        rows = list_host_group_rows(cur)

    return [HostGroupOut(**host_group_row_to_dict(row)) for row in rows]


@app.get("/host-groups/tree", response_model=List[dict[str, Any]])
def list_host_groups_tree():
    with get_conn() as conn, conn.cursor() as cur:
        if not has_host_groups_schema(cur):
            return []

        rows = list_host_group_rows(cur)

    groups = [host_group_row_to_dict(row) for row in rows]
    return build_host_groups_tree(groups)


@app.post("/host-groups", response_model=HostGroupOut)
def create_host_group(payload: HostGroupIn):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_host_groups_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de grupos de hosts ainda não foi inicializado.")

        parent_id = payload.parent_id
        if parent_id is not None:
            get_host_group_record(cur, parent_id)

        slug, path = build_host_group_slug_and_path(cur, payload.name, parent_id=parent_id)

        cur.execute(
            """
            INSERT INTO host_groups (name, slug, parent_id, path, tags, enabled)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, name, slug, parent_id, path, tags, enabled
            """,
            (
                payload.name,
                slug,
                parent_id,
                path,
                psycopg.types.json.Json(payload.tags or {}),
                payload.enabled,
            ),
        )
        row = cur.fetchone()
        conn.commit()

    return HostGroupOut(**host_group_row_to_dict(row))


@app.put("/host-groups/{group_id}", response_model=HostGroupOut)
def update_host_group(group_id: int, payload: HostGroupIn):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_host_groups_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de grupos de hosts ainda não foi inicializado.")

        current_group = get_host_group_record(cur, group_id)
        parent_id = payload.parent_id

        if parent_id == group_id:
            raise HTTPException(status_code=400, detail="Host group cannot be its own parent")

        if parent_id is not None:
            parent_group = get_host_group_record(cur, parent_id)
            parent_path = parent_group["path"]
            if parent_path == current_group["path"] or parent_path.startswith(f"{current_group['path']}/"):
                raise HTTPException(status_code=400, detail="Host group parent would create a cycle")

        slug, path = build_host_group_slug_and_path(
            cur,
            payload.name,
            parent_id=parent_id,
            exclude_id=group_id,
        )

        cur.execute(
            """
            UPDATE host_groups
            SET name = %s,
                slug = %s,
                parent_id = %s,
                path = %s,
                tags = %s,
                enabled = %s
            WHERE id = %s
            RETURNING id, name, slug, parent_id, path, tags, enabled
            """,
            (
                payload.name,
                slug,
                parent_id,
                path,
                psycopg.types.json.Json(payload.tags or {}),
                payload.enabled,
                group_id,
            ),
        )
        row = cur.fetchone()
        update_host_group_descendant_paths(cur, current_group["path"], path)
        conn.commit()

    return HostGroupOut(**host_group_row_to_dict(row))


@app.get("/profiles", response_model=List[ProfileOut])
def list_profiles():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT id, name, display_name, kind, description, config, enabled
            FROM monitoring_profiles
            WHERE enabled = true
            ORDER BY display_name
        """)
        rows = cur.fetchall()

    return [
        ProfileOut(
            id=r[0],
            name=r[1],
            display_name=r[2] or r[1],
            kind=r[3],
            description=r[4],
            config=r[5] or {},
            enabled=r[6]
        )
        for r in rows
    ]


@app.get("/templates", response_model=List[MonitoringTemplateOut])
def list_templates():
    with get_conn() as conn, conn.cursor() as cur:
        if not has_monitoring_templates_schema(cur):
            return []

        templates = list_monitoring_template_records(cur)

    return [MonitoringTemplateOut(**template) for template in templates]


@app.get("/templates/{template_id}", response_model=MonitoringTemplateOut)
def get_template(template_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_monitoring_templates_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de templates ainda não foi inicializado.")

        template = get_monitoring_template_record(cur, template_id)

    return MonitoringTemplateOut(**template)


@app.get("/templates/{template_id}/preview", response_model=MonitoringTemplatePreviewOut)
def get_template_preview(template_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_monitoring_templates_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de templates ainda não foi inicializado.")

        template = get_monitoring_template_record(cur, template_id)

    return MonitoringTemplatePreviewOut(
        id=template["id"],
        name=template["name"],
        slug=template["slug"],
        asset_type=template["asset_type"],
        vendor=template["vendor"],
        family=template["family"],
        summary=template["summary"],
        capabilities=template["capabilities"],
        preview=template["preview"],
        collection_policy=template["collection_policy"],
        enabled=template["enabled"],
        profiles=[TemplateProfileOut(**profile) for profile in template["profiles"]],
    )


@app.put("/templates/{template_id}/collection-policy", response_model=MonitoringTemplateOut)
def save_template_collection_policy(template_id: int, payload: CollectionPolicyIn):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_monitoring_templates_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de templates ainda não foi inicializado.")

        template = update_template_collection_policy(cur, template_id, payload)
        conn.commit()

    return MonitoringTemplateOut(**template)


@app.get("/templates/{template_id}/items", response_model=List[MonitoringItemOut])
def list_template_items(template_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_monitoring_templates_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de templates ainda não foi inicializado.")
        get_monitoring_template_record(cur, template_id)
        items = list_template_monitoring_items(cur, template_id)
    return [MonitoringItemOut(**item) for item in items]


@app.get("/hosts/{host_id}/monitoring-items", response_model=List[MonitoringItemOut])
def list_host_monitoring_items_endpoint(host_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        get_host_record(cur, host_id)
        items = list_host_monitoring_items(cur, host_id)
        conn.commit()
    return [MonitoringItemOut(**item) for item in items]


@app.post("/hosts/{host_id}/template", response_model=HostOut)
def apply_host_template(host_id: int, payload: ApplyTemplateIn):
    with get_conn() as conn, conn.cursor() as cur:
        host = apply_template_to_host(cur, host_id, payload)
        attach_host_operational_state(cur, [host])
        conn.commit()
    return HostOut(**host_api_payload(host))


@app.put("/monitoring/items/{item_id}", response_model=MonitoringItemOut)
def save_monitoring_item(item_id: int, payload: MonitoringItemIn):
    with get_conn() as conn, conn.cursor() as cur:
        item = update_monitoring_item(cur, item_id, payload)
        conn.commit()
    return MonitoringItemOut(**item)


@app.patch("/monitoring/items/{item_id}/enabled", response_model=MonitoringItemOut)
def toggle_monitoring_item(item_id: int, payload: MonitoringItemToggleIn):
    with get_conn() as conn, conn.cursor() as cur:
        item = update_monitoring_item(cur, item_id, MonitoringItemIn(enabled=payload.enabled))
        conn.commit()
    return MonitoringItemOut(**item)


@app.post("/discovery/scan", response_model=NetworkDiscoveryRunOut)
def start_network_discovery(payload: NetworkDiscoveryScanIn):
    try:
        network = ipaddress.ip_network(payload.cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="CIDR inválido.") from exc
    if network.num_addresses > 256:
        raise HTTPException(status_code=400, detail="Discovery acima de /24 está bloqueado no MVP.")
    if not payload.use_icmp and not payload.use_snmp:
        raise HTTPException(status_code=400, detail="Selecione ICMP ou SNMP para executar a descoberta.")

    hosts = [str(ip) for ip in network.hosts()]
    if network.num_addresses <= 2:
        hosts = [str(network.network_address)]

    with get_conn() as conn, conn.cursor() as cur:
        if not has_network_discovery_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de discovery ainda não foi inicializado.")
        cur.execute(
            """
            INSERT INTO network_discovery_runs (
                cidr, timeout_seconds, retries, use_icmp, use_snmp,
                snmp_community_masked, status, total_ips, requested_by, audit
            )
            VALUES (%s,%s,%s,%s,%s,%s,'running',%s,%s,%s)
            RETURNING id
            """,
            (
                str(network),
                payload.timeout_seconds,
                payload.retries,
                payload.use_icmp,
                payload.use_snmp,
                mask_secret(payload.snmp_community),
                len(hosts),
                payload.requested_by,
                psycopg.types.json.Json({"max_scope": "/24", "execution": "synchronous"}),
            ),
        )
        run_id = cur.fetchone()[0]
        conn.commit()

    results: list[dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=min(32, max(1, len(hosts)))) as executor:
            futures = [executor.submit(scan_discovery_ip, ip, payload) for ip in hosts]
            for future in as_completed(futures):
                results.append(future.result())
    except Exception as exc:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE network_discovery_runs
                SET status='failed', finished_at=now(), error=%s
                WHERE id=%s
                """,
                (str(exc), run_id),
            )
            conn.commit()
        raise HTTPException(status_code=500, detail="Falha ao executar discovery.") from exc

    with get_conn() as conn, conn.cursor() as cur:
        active_count = 0
        snmp_count = 0
        for result in sorted(results, key=lambda item: ipaddress.ip_address(item["ip"])):
            is_active = result["icmp_status"] == "up" or result["snmp_status"] == "up"
            if not is_active:
                continue
            active_count += 1
            if result["snmp_status"] == "up":
                snmp_count += 1
            cur.execute(
                f"SELECT id FROM {ASSETS_TABLE} WHERE ip::text=%s LIMIT 1",
                (result["ip"],),
            )
            existing = cur.fetchone()
            template_id = get_template_id_by_slug(cur, result["suggested_template_slug"])
            template_name = None
            if template_id:
                cur.execute("SELECT name FROM monitoring_templates WHERE id=%s", (template_id,))
                template_row = cur.fetchone()
                template_name = template_row[0] if template_row else None
            cur.execute(
                """
                INSERT INTO network_discovery_results (
                    run_id, ip, icmp_status, snmp_status, sys_name, sys_descr,
                    sys_object_id, sys_uptime, detected_vendor, suggested_template_id,
                    suggested_template_slug, suggested_template_name,
                    already_registered, existing_host_id, raw
                )
                VALUES (%s,%s::inet,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (run_id, ip) DO UPDATE SET
                    icmp_status=EXCLUDED.icmp_status,
                    snmp_status=EXCLUDED.snmp_status,
                    sys_name=EXCLUDED.sys_name,
                    sys_descr=EXCLUDED.sys_descr,
                    sys_object_id=EXCLUDED.sys_object_id,
                    sys_uptime=EXCLUDED.sys_uptime,
                    detected_vendor=EXCLUDED.detected_vendor,
                    suggested_template_id=EXCLUDED.suggested_template_id,
                    suggested_template_slug=EXCLUDED.suggested_template_slug,
                    suggested_template_name=EXCLUDED.suggested_template_name,
                    already_registered=EXCLUDED.already_registered,
                    existing_host_id=EXCLUDED.existing_host_id,
                    raw=EXCLUDED.raw
                """,
                (
                    run_id,
                    result["ip"],
                    result["icmp_status"],
                    result["snmp_status"],
                    result["sys_name"],
                    result["sys_descr"],
                    result["sys_object_id"],
                    result["sys_uptime"],
                    result["detected_vendor"],
                    template_id,
                    result["suggested_template_slug"],
                    template_name,
                    existing is not None,
                    existing[0] if existing else None,
                    psycopg.types.json.Json(result["raw"] or {}),
                ),
            )
        cur.execute(
            """
            UPDATE network_discovery_runs
            SET status='completed', finished_at=now(), active_hosts=%s, snmp_hosts=%s
            WHERE id=%s
            RETURNING id, cidr, timeout_seconds, retries, use_icmp, use_snmp,
                      snmp_community_masked, status, started_at, finished_at,
                      total_ips, active_hosts, snmp_hosts, imported_hosts,
                      error, requested_by, audit
            """,
            (active_count, snmp_count, run_id),
        )
        run_row = cur.fetchone()
        run_results = list_discovery_results(cur, run_id)
        cur.execute(
            """
            INSERT INTO audit_events (actor, action, target_type, target_id, details)
            VALUES (%s, 'network_discovery.scan', 'network_discovery_run', %s, %s)
            """,
            (
                payload.requested_by,
                str(run_id),
                psycopg.types.json.Json({"cidr": str(network), "active_hosts": active_count, "snmp_hosts": snmp_count}),
            ),
        )
        conn.commit()

    return NetworkDiscoveryRunOut(**discovery_run_row_to_dict(run_row, run_results))


@app.get("/discovery/runs", response_model=List[NetworkDiscoveryRunOut])
def list_network_discovery_runs(limit: int = Query(20, ge=1, le=100)):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_network_discovery_schema(cur):
            return []
        cur.execute(
            """
            SELECT id, cidr, timeout_seconds, retries, use_icmp, use_snmp,
                   snmp_community_masked, status, started_at, finished_at,
                   total_ips, active_hosts, snmp_hosts, imported_hosts,
                   error, requested_by, audit
            FROM network_discovery_runs
            ORDER BY started_at DESC, id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
    return [NetworkDiscoveryRunOut(**discovery_run_row_to_dict(row)) for row in rows]


@app.get("/discovery/runs/{run_id}/results", response_model=List[NetworkDiscoveryResultOut])
def list_network_discovery_results(run_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_network_discovery_schema(cur):
            return []
        return [NetworkDiscoveryResultOut(**item) for item in list_discovery_results(cur, run_id)]


@app.post("/discovery/results/{result_id}/promote")
def promote_network_discovery_result(result_id: int, payload: Optional[NetworkDiscoveryImportIn] = None):
    request = payload or NetworkDiscoveryImportIn(result_ids=[result_id])
    with get_conn() as conn, conn.cursor() as cur:
        if not has_network_discovery_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de discovery ainda não foi inicializado.")
        host_id = import_discovery_result(
            cur,
            result_id,
            request.group_id,
            request.enable_hosts,
            request.snmp_community,
        )
        conn.commit()
    return {"ok": True, "host_id": host_id}


@app.post("/discovery/import")
def import_network_discovery_results(payload: NetworkDiscoveryImportIn):
    if not payload.result_ids:
        raise HTTPException(status_code=400, detail="Selecione pelo menos um resultado para importar.")
    imported: list[int] = []
    with get_conn() as conn, conn.cursor() as cur:
        if not has_network_discovery_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de discovery ainda não foi inicializado.")
        for result_id in payload.result_ids:
            host_id = import_discovery_result(
                cur,
                result_id,
                payload.group_id,
                payload.enable_hosts,
                payload.snmp_community,
            )
            if host_id is not None:
                imported.append(int(host_id))
        cur.execute(
            """
            INSERT INTO audit_events (actor, action, target_type, details)
            VALUES (%s, 'network_discovery.import', 'asset', %s)
            """,
            (
                None,
                psycopg.types.json.Json({"result_ids": payload.result_ids, "host_ids": imported}),
            ),
        )
        conn.commit()
    return {"ok": True, "imported_host_ids": imported}


@app.get("/dashboards/ops", response_model=List[GrafanaDashboardOut])
def list_ops_dashboards(
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)

    dashboard = build_grafana_dashboard(
        "ops_overview",
        owner_type="ops",
        title="Visão operacional",
        description="Dashboard geral do NetGuard com contexto operacional, saúde, incidentes, loop_risk e sinais recentes.",
        tags=["Monitoramento", "Operação v2"],
        context={"scope": "global"},
        from_ts=parsed_from,
        to_ts=parsed_to,
    )
    return [GrafanaDashboardOut(**dashboard)]


@app.get("/dashboards/host/{host_id}", response_model=List[GrafanaDashboardOut])
def list_host_dashboards(
    host_id: int,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)

    with get_conn() as conn, conn.cursor() as cur:
        host = get_host_record(cur, host_id)

    dashboard_key = resolve_host_dashboard_key(host)
    template_label = host.get("template_name") or "Sem template legado"
    group_label = host.get("group_path") or host.get("group_name") or "Sem grupo legado"

    dashboard = build_grafana_dashboard(
        dashboard_key,
        owner_type="host",
        owner_id=host_id,
        variables={"asset_id": host_id},
        title=f"Visualização de {host['name']}",
        description=f"Dashboard Grafana do host {host['name']}, alinhado ao template {template_label}.",
        tags=[host["name"], group_label, template_label],
        context={
            "host_name": host["name"],
            "host_ip": host["ip"],
            "group_name": group_label,
            "template_name": template_label,
            "template_slug": host.get("template_slug"),
        },
        from_ts=parsed_from,
        to_ts=parsed_to,
    )
    return [GrafanaDashboardOut(**dashboard)]


@app.get("/dashboards/group/{group_id}", response_model=List[GrafanaDashboardOut])
def list_group_dashboards(
    group_id: int,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)

    with get_conn() as conn, conn.cursor() as cur:
        if not has_host_groups_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de grupos de hosts ainda não foi inicializado.")

        group = get_host_group_record(cur, group_id)

    dashboard = build_grafana_dashboard(
        "ops_overview",
        owner_type="group",
        owner_id=group_id,
        variables={"group_id": group_id},
        title=f"Visão do grupo {group['name']}",
        description=f"Dashboard operacional filtrado para o grupo {group['path']}.",
        tags=[group["path"], "Grupo de hosts"],
        context={"group_name": group["name"], "group_path": group["path"]},
        from_ts=parsed_from,
        to_ts=parsed_to,
    )
    return [GrafanaDashboardOut(**dashboard)]


@app.get("/dashboards/template/{template_id}", response_model=List[GrafanaDashboardOut])
def list_template_dashboards(
    template_id: int,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)

    with get_conn() as conn, conn.cursor() as cur:
        if not has_monitoring_templates_schema(cur):
            raise HTTPException(status_code=503, detail="O schema de templates ainda não foi inicializado.")

        template = get_monitoring_template_record(cur, template_id)
        host_dashboard_key = resolve_host_dashboard_key(
            {
                "template_slug": template["slug"],
                "template_asset_type": template["asset_type"],
            }
        )

    dashboard = build_grafana_dashboard(
        "ops_overview",
        owner_type="template",
        owner_id=template_id,
        variables={"template_id": template_id},
        title=f"Visão do template {template['name']}",
        description=(
            f"Dashboard operacional filtrado para hosts com o template {template['name']}. "
            f"Quando aplicado a um host, o dashboard principal sugerido é {GRAFANA_DASHBOARD_REGISTRY[host_dashboard_key]['title']}."
        ),
        tags=[template["name"], template["asset_type"], "Template"],
        context={
            "template_name": template["name"],
            "template_slug": template["slug"],
            "recommended_host_dashboard_key": host_dashboard_key,
        },
        from_ts=parsed_from,
        to_ts=parsed_to,
    )
    return [GrafanaDashboardOut(**dashboard)]


@app.get("/ai/insights", response_model=List[AIInsightOut])
def list_ai_insights(
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    insight_type: Optional[str] = None,
    include_expired: bool = False,
    limit: int = 50,
):
    with get_conn() as conn, conn.cursor() as cur:
        if not has_ai_insights_schema(cur):
            raise HTTPException(status_code=503, detail="A tabela de ai_insights ainda não foi inicializada no banco.")

        insights = list_ai_insight_records(
            cur,
            target_type=target_type,
            target_id=target_id,
            insight_type=insight_type,
            include_expired=include_expired,
            limit=limit,
        )

    return [AIInsightOut(**insight) for insight in insights]


@app.post("/ai/chat", response_model=AIChatOut)
def contextual_ai_chat(payload: AIChatRequestIn):
    history_payload = [
        {
            "role": str(item.role or "").strip().lower(),
            "content": str(item.content or "").strip(),
        }
        for item in payload.history
        if str(item.content or "").strip()
    ]

    with get_conn() as conn, conn.cursor() as cur:
        context = build_chat_ai_context(
            cur,
            message=payload.message,
            host_id=payload.host_id,
            incident_id=payload.incident_id,
            hours=payload.hours,
        )

    enrich_active_operational_brief_for_chat(context)
    intent_detected = classify_ai_chat_intent(payload.message, context)
    response_mode = choose_ai_response_mode(payload.response_mode, intent_detected, payload.message, context)
    generated_at = to_iso(datetime.now(timezone.utc)) or ""

    if response_mode == "fast":
        reply = build_deterministic_chat_reply(payload.message, context, intent_detected)
        return AIChatOut(
            model="NetGuard",
            reply_md=reply,
            generated_at=generated_at,
            context_scope=context.get("scope_context") or {},
            evidence_json={
                "scope": "chat",
                "question_kind": context.get("question_kind"),
                "question_intent": context.get("question_intent"),
                "intent_detected": intent_detected,
                "response_mode": response_mode,
                "active_operational_brief": context.get("active_operational_brief") or {},
            },
            answer_source="deterministic",
            model_used="NetGuard",
            intent_detected=intent_detected,
            response_mode=response_mode,
            llm_latency_ms=0,
        )

    prompt = (
        build_hybrid_ai_chat_prompt(payload.message, context, history_payload, intent_detected)
        if response_mode == "hybrid"
        else build_ai_chat_prompt(payload.message, context, history_payload)
    )
    llm_start = time_module.perf_counter()
    try:
        result = generate_ai_text(
            system=AI_CHAT_SYSTEM_PROMPT,
            prompt=prompt,
            temperature=0.1,
            num_predict=260 if response_mode == "hybrid" else 420,
            allow_retry=False,
        )
        llm_latency_ms = int((time_module.perf_counter() - llm_start) * 1000)
        return AIChatOut(
            model=result.model,
            reply_md=clean_ai_chat_reply(result.response),
            generated_at=generated_at,
            context_scope=context.get("scope_context") or {},
            evidence_json={
                **context,
                "intent_detected": intent_detected,
                "response_mode": response_mode,
                "answer_source": "hybrid" if response_mode == "hybrid" else "ollama",
                "llm_latency_ms": llm_latency_ms,
            },
            answer_source="hybrid" if response_mode == "hybrid" else "ollama",
            model_used=result.model,
            intent_detected=intent_detected,
            response_mode=response_mode,
            llm_latency_ms=llm_latency_ms,
        )
    except OllamaClientError as exc:
        llm_latency_ms = int((time_module.perf_counter() - llm_start) * 1000)
        fallback_reply = build_ai_unavailable_chat_reply(payload.message, context, str(exc))

        return AIChatOut(
            model="NetGuard fallback",
            reply_md=fallback_reply,
            generated_at=generated_at,
            context_scope=context.get("scope_context") or {},
            evidence_json={
                "scope": "chat",
                "question_kind": context.get("question_kind"),
                "question_intent": context.get("question_intent"),
                "intent_detected": intent_detected,
                "response_mode": response_mode,
                "fallback": "ollama_unavailable",
                "ollama_error": str(exc),
                "active_operational_brief": context.get("active_operational_brief") or {},
            },
            answer_source="fallback",
            model_used="NetGuard fallback",
            intent_detected=intent_detected,
            response_mode=response_mode,
            llm_latency_ms=llm_latency_ms,
            fallback_reason=str(exc),
        )


@app.post("/ai/hosts/{host_id}/summary", response_model=AIInsightOut)
def generate_host_summary(host_id: int, payload: Optional[AIInsightTriggerIn] = None):
    payload = payload or AIInsightTriggerIn()
    with get_conn() as conn, conn.cursor() as cur:
        context = build_host_ai_context(cur, host_id, hours=24)
        insight = generate_ai_insight(
            cur,
            target_type="host",
            target_id=host_id,
            insight_type="host_summary",
            context=context,
            refresh=payload.refresh,
        )
        conn.commit()

    return AIInsightOut(**insight)


@app.post("/ai/hosts/{host_id}/recommendation", response_model=AIInsightOut)
def generate_host_recommendation(host_id: int, payload: Optional[AIInsightTriggerIn] = None):
    payload = payload or AIInsightTriggerIn()
    with get_conn() as conn, conn.cursor() as cur:
        context = build_host_ai_context(cur, host_id, hours=24)
        insight = generate_ai_insight(
            cur,
            target_type="host",
            target_id=host_id,
            insight_type="operational_recommendation",
            context=context,
            refresh=payload.refresh,
        )
        conn.commit()

    return AIInsightOut(**insight)


@app.post("/ai/incidents/{incident_id}/explain", response_model=AIInsightOut)
def explain_incident(incident_id: int, payload: Optional[AIInsightTriggerIn] = None):
    payload = payload or AIInsightTriggerIn()
    with get_conn() as conn, conn.cursor() as cur:
        context = build_incident_ai_context(cur, incident_id)
        insight = generate_ai_insight(
            cur,
            target_type="incident",
            target_id=incident_id,
            insight_type="incident_explanation",
            context=context,
            refresh=payload.refresh,
        )
        conn.commit()

    return AIInsightOut(**insight)


@app.post("/ai/reports/technical-summary", response_model=AIInsightOut)
def generate_technical_summary(payload: Optional[TechnicalSummaryIn] = None):
    payload = payload or TechnicalSummaryIn()
    with get_conn() as conn, conn.cursor() as cur:
        target_id, context = build_technical_summary_context(
            cur,
            requested_host_id=payload.host_id,
            incident_id=payload.incident_id,
        )
        insight = generate_ai_insight(
            cur,
            target_type="report",
            target_id=target_id,
            insight_type="technical_summary",
            context=context,
            refresh=payload.refresh,
        )
        conn.commit()

    return AIInsightOut(**insight)

@app.get("/hosts", response_model=List[HostOut])
def list_hosts(
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    q: Optional[str] = None,
    enabled: Optional[bool] = None,
    health: Optional[str] = None,
    severity: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 500,
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)
    normalized_health = normalize_status_value(health)
    normalized_severity = normalize_severity_value(severity)
    normalized_limit = normalize_limit(limit, default=500, maximum=2000)
    fetch_limit = (
        min(max(normalized_limit * 5, 500), 5000)
        if any([normalized_health, normalized_severity, parsed_from, parsed_to])
        else normalized_limit
    )

    with get_conn() as conn, conn.cursor() as cur:
        groups_ready = has_host_groups_schema(cur)
        templates_ready = has_monitoring_templates_schema(cur)
        collection_policy_ready = has_assets_collection_policy_schema(cur)
        query = (
            f"SELECT {', '.join(build_host_select_parts(groups_ready, templates_ready, collection_policy_ready))} "
            f"FROM {ASSETS_TABLE} a"
        )

        if groups_ready:
            query += " LEFT JOIN host_groups g ON g.id = a.group_id"

        if templates_ready:
            query += " LEFT JOIN monitoring_templates t ON t.id = a.template_id"

        conditions: list[str] = []
        params: list[Any] = []

        if groups_ready and group_id is not None:
            conditions.append("a.group_id = %s")
            params.append(group_id)

        if templates_ready and template_id is not None:
            conditions.append("a.template_id = %s")
            params.append(template_id)

        if enabled is not None:
            conditions.append("a.enabled = %s")
            params.append(enabled)

        append_text_search(
            conditions,
            params,
            q,
            [
                "a.name",
                "a.ip::text",
                "g.name" if groups_ready else "NULL",
                "g.path" if groups_ready else "NULL",
                "t.name" if templates_ready else "NULL",
                "t.vendor" if templates_ready else "NULL",
                "t.family" if templates_ready else "NULL",
            ],
        )

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.id LIMIT %s"
        params.append(fetch_limit)
        cur.execute(query, params)
        rows = cur.fetchall()

        hosts = [
            host_row_to_dict(row, groups_ready, templates_ready, collection_policy_ready)
            for row in rows
        ]
        hosts = attach_host_operational_state(cur, hosts, parsed_from, parsed_to)

    filtered_hosts: list[dict[str, Any]] = []
    for host in hosts:
        if normalized_health and host.get("health_status") != normalized_health:
            continue

        if normalized_severity:
            host_severity = host.get("max_incident_severity")
            if normalized_severity == "none":
                if host_severity is not None:
                    continue
            elif host_severity != normalized_severity:
                continue

        if parsed_from or parsed_to:
            reference_value = parse_datetime_filter(host.get("last_activity_at")) if host.get("last_activity_at") else None
            if reference_value is None:
                continue
            if parsed_from is not None and reference_value < parsed_from:
                continue
            if parsed_to is not None and reference_value > parsed_to:
                continue

        filtered_hosts.append(host)

    return [HostOut(**host_api_payload(host)) for host in filtered_hosts[:normalized_limit]]


@app.get("/hosts/{host_id}", response_model=HostOut)
def get_host(host_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        host = get_host_record(cur, host_id)
        attach_host_operational_state(cur, [host])

    return HostOut(**host_api_payload(host))


@app.post("/hosts/{host_id}/collect-now", response_model=CollectNowOut)
def collect_host_now(host_id: int, payload: Optional[CollectNowIn] = None):
    payload = payload or CollectNowIn()

    with get_conn() as conn, conn.cursor() as cur:
        get_host_record(cur, host_id)
        request = queue_collection_request(cur, host_id, payload.protocol)
        conn.commit()

    return CollectNowOut(**request)

@app.get("/hosts/{host_id}/profiles", response_model=List[HostProfileOut])
def get_host_profiles(host_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT 1 FROM {ASSETS_TABLE} WHERE id=%s", (host_id,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="Host não encontrado.")

        cur.execute("""
            SELECT
                mp.id,
                mp.name,
                mp.display_name,
                mp.kind,
                mp.description,
                mp.config,
                ap.params,
                ap.enabled
            FROM asset_profiles ap
            JOIN monitoring_profiles mp ON mp.id = ap.profile_id
            WHERE ap.asset_id = %s
            ORDER BY mp.display_name
        """, (host_id,))
        rows = cur.fetchall()

    return [
        HostProfileOut(
            profile_id=r[0],
            name=r[1],
            display_name=r[2] or r[1],
            kind=r[3],
            description=r[4],
            config=r[5] or {},
            params=r[6] or {},
            enabled=r[7]
        )
        for r in rows
    ]

@app.post("/hosts", response_model=HostOut)
def create_host(host: HostIn):
    with get_conn() as conn, conn.cursor() as cur:
        groups_ready = has_host_groups_schema(cur)
        templates_ready = has_monitoring_templates_schema(cur)
        collection_policy_ready = has_assets_collection_policy_schema(cur)

        normalized_group_id = normalize_group_id(cur, host.group_id)
        normalized_template_id = normalize_template_id(cur, host.template_id)
        normalized_policy_override = normalize_collection_policy(host.collection_policy_override or {})

        if groups_ready and normalized_group_id is None:
            raise HTTPException(status_code=400, detail="group_id is required for host persistence")

        insert_columns = ["name", "ip", "snmp_profile", "tags"]
        insert_values: list[Any] = [
            host.name,
            str(host.ip),
            psycopg.types.json.Json(host.snmp_profile or {}),
            psycopg.types.json.Json(host.tags or {}),
        ]

        if groups_ready:
            insert_columns.append("group_id")
            insert_values.append(normalized_group_id)

        if templates_ready:
            insert_columns.append("template_id")
            insert_values.append(normalized_template_id)

        if collection_policy_ready:
            insert_columns.append("collection_policy_override")
            insert_values.append(psycopg.types.json.Json(normalized_policy_override))

        insert_columns.append("enabled")
        insert_values.append(host.enabled)

        cur.execute(
            f"""
            INSERT INTO {ASSETS_TABLE} ({', '.join(insert_columns)})
            VALUES ({', '.join(['%s'] * len(insert_values))})
            RETURNING id
            """,
            insert_values,
        )
        new_id = cur.fetchone()[0]
        conn.commit()

        created_host = get_host_record(cur, new_id)

    return HostOut(**host_api_payload(created_host))

@app.put("/hosts/{host_id}", response_model=HostOut)
def update_host(host_id: int, host: HostIn):
    with get_conn() as conn, conn.cursor() as cur:
        groups_ready = has_host_groups_schema(cur)
        templates_ready = has_monitoring_templates_schema(cur)
        collection_policy_ready = has_assets_collection_policy_schema(cur)
        cur.execute(f"SELECT enabled, name, ip FROM {ASSETS_TABLE} WHERE id=%s", (host_id,))
        current_host = cur.fetchone()
        if current_host is None:
            raise HTTPException(status_code=404, detail="Host não encontrado.")

        was_enabled = bool(current_host[0])
        previous_name = current_host[1]
        previous_ip = str(current_host[2]) if current_host[2] is not None else None

        normalized_group_id = normalize_group_id(cur, host.group_id)
        normalized_template_id = normalize_template_id(cur, host.template_id)
        normalized_policy_override = normalize_collection_policy(host.collection_policy_override or {})

        if groups_ready and normalized_group_id is None:
            raise HTTPException(status_code=400, detail="group_id is required for host persistence")

        update_parts = [
            "name=%s",
            "ip=%s",
            "snmp_profile=%s",
            "tags=%s",
        ]
        update_values: list[Any] = [
            host.name,
            str(host.ip),
            psycopg.types.json.Json(host.snmp_profile or {}),
            psycopg.types.json.Json(host.tags or {}),
        ]

        if groups_ready:
            update_parts.append("group_id=%s")
            update_values.append(normalized_group_id)

        if templates_ready:
            update_parts.append("template_id=%s")
            update_values.append(normalized_template_id)

        if collection_policy_ready:
            update_parts.append("collection_policy_override=%s")
            update_values.append(psycopg.types.json.Json(normalized_policy_override))

        update_parts.append("enabled=%s")
        update_values.extend([host.enabled, host_id])

        cur.execute(
            f"UPDATE {ASSETS_TABLE} SET {', '.join(update_parts)} WHERE id=%s",
            update_values
        )

        if was_enabled and not host.enabled:
            resolve_open_incidents_for_disabled_host(
                cur,
                host_id,
                host_name=host.name or previous_name,
                host_ip=str(host.ip) if host.ip is not None else previous_ip,
            )

        conn.commit()

        updated_host = get_host_record(cur, host_id)

    return HostOut(**host_api_payload(updated_host))

@app.put("/hosts/{host_id}/profiles")
def update_host_profiles(host_id: int, payload: HostProfilesUpdate):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT 1 FROM {ASSETS_TABLE} WHERE id=%s", (host_id,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="Host não encontrado.")

        cur.execute("DELETE FROM asset_profiles WHERE asset_id = %s", (host_id,))

        for item in payload.profiles:
            cur.execute("""
                INSERT INTO asset_profiles (asset_id, profile_id, params, enabled)
                VALUES (%s, %s, %s, %s)
            """, (
                host_id,
                item.profile_id,
                psycopg.types.json.Json(item.params or {}),
                item.enabled
            ))

        conn.commit()

    return {"ok": True}

@app.delete("/hosts/{host_id}")
def delete_host(host_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f"DELETE FROM {ASSETS_TABLE} WHERE id=%s", (host_id,))
        conn.commit()
    return {"ok": True}

@app.post("/hosts/{host_id}/discover-interfaces", response_model=DiscoveryResponse)
def discover_interfaces(host_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT id, ip, snmp_profile FROM {ASSETS_TABLE} WHERE id=%s",
            (host_id,)
        )
        row = cur.fetchone()

        if row is None:
            raise HTTPException(status_code=404, detail="Host não encontrado.")

        asset_id = row[0]
        ip = str(row[1])
        snmp_profile = row[2] or {}
        rows = discover_interfaces_for_asset(cur, asset_id, ip, snmp_profile)
        conn.commit()

    return DiscoveryResponse(
        host_id=asset_id,
        interfaces=[DiscoveredInterfaceOut(**discovered_interface_row_to_dict(r)) for r in rows],
    )


@app.post("/lab/bootstrap", response_model=LabBootstrapOut)
def bootstrap_lab_host():
    return bootstrap_lab_host_internal()

@app.get("/hosts/{host_id}/interfaces", response_model=List[DiscoveredInterfaceOut])
def list_discovered_interfaces(host_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT 1 FROM {ASSETS_TABLE} WHERE id=%s",
            (host_id,)
        )
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="Host não encontrado.")

        cur.execute(
            f"""
            SELECT {DISCOVERED_INTERFACE_SELECT}
            FROM discovered_interfaces
            WHERE asset_id=%s
            ORDER BY ifindex
            """,
            (host_id,)
        )
        rows = cur.fetchall()

    return [DiscoveredInterfaceOut(**discovered_interface_row_to_dict(r)) for r in rows]


@app.put("/hosts/{host_id}/interfaces/{interface_id}", response_model=DiscoveredInterfaceOut)
def update_discovered_interface_selection(
    host_id: int,
    interface_id: int,
    payload: UpdateDiscoveredInterfaceSelectionIn
):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE discovered_interfaces
            SET selected=%s, updated_at=now()
            WHERE id=%s AND asset_id=%s
            RETURNING id, asset_id, ifindex, ifdescr, if_name, if_alias, admin_status, oper_status,
                      last_seen_at, last_change, speed_bps, mac_address,
                      last_in_octets, last_out_octets, last_in_errors, last_out_errors,
                      last_in_discards, last_out_discards, last_in_bps, last_out_bps,
                      last_error, selected
            """,
            (payload.selected, interface_id, host_id)
        )
        row = cur.fetchone()

        if row is None:
            raise HTTPException(status_code=404, detail="Interface descoberta não encontrada.")

        conn.commit()

    return DiscoveredInterfaceOut(**discovered_interface_row_to_dict(row))


@app.get("/hosts/{host_id}/correlations", response_model=List[SyslogInterfaceCorrelationOut])
def list_host_syslog_correlations(host_id: int, limit: int = Query(100, ge=1, le=500)):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT 1 FROM {ASSETS_TABLE} WHERE id=%s", (host_id,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="Host não encontrado.")
        if not has_syslog_correlation_schema(cur):
            return []
        cur.execute(
            """
            SELECT
                c.id,
                c.asset_id,
                c.syslog_event_id,
                c.interface_id,
                c.ifindex,
                c.normalized_iface,
                c.confidence,
                c.evidence,
                c.created_at,
                e.ts,
                e.severity,
                e.subsystem,
                e.message,
                d.ifdescr,
                d.if_name,
                d.if_alias
            FROM syslog_interface_correlations c
            LEFT JOIN syslog_events e ON e.id = c.syslog_event_id
            LEFT JOIN discovered_interfaces d ON d.id = c.interface_id
            WHERE c.asset_id=%s
            ORDER BY COALESCE(e.ts, c.created_at) DESC, c.id DESC
            LIMIT %s
            """,
            (host_id, limit),
        )
        rows = cur.fetchall()
    return [
        SyslogInterfaceCorrelationOut(
            id=row[0],
            asset_id=row[1],
            syslog_event_id=row[2],
            interface_id=row[3],
            ifindex=row[4],
            normalized_iface=row[5],
            confidence=float(row[6] or 0),
            evidence=row[7] or {},
            created_at=to_iso(row[8]),
            event_ts=to_iso(row[9]),
            event_severity=row[10],
            event_subsystem=row[11],
            event_message=row[12],
            ifdescr=row[13],
            if_name=row[14],
            if_alias=row[15],
        )
        for row in rows
    ]


@app.get("/hosts/{host_id}/loop-risk/evidence")
def get_host_loop_risk_evidence(host_id: int, minutes: int = Query(5, ge=1, le=1440)):
    window_start = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    with get_conn() as conn, conn.cursor() as cur:
        host = get_host_record(cur, host_id)
        cur.execute(
            """
            SELECT id, title, severity, status, opened_at, last_seen_at, details
            FROM incidents
            WHERE asset_id=%s
              AND LOWER(status) IN ('open','acknowledged')
              AND LOWER(incident_type) IN ('loop_risk','snmp_collection_silence','icmp_collection_silence')
            ORDER BY opened_at DESC
            LIMIT 10
            """,
            (host_id,),
        )
        incidents = [
            {
                "id": row[0],
                "title": row[1],
                "severity": row[2],
                "status": row[3],
                "opened_at": to_iso(row[4]),
                "last_seen_at": to_iso(row[5]),
                "details": row[6] or {},
            }
            for row in cur.fetchall()
        ]
        cur.execute(
            """
            SELECT ts, score, key, value, details
            FROM anomaly_scores
            WHERE asset_id=%s
              AND metric='loop_risk'
            ORDER BY ts DESC
            LIMIT 5
            """,
            (host_id,),
        )
        predictions = [
            {
                "ts": to_iso(row[0]),
                "score": float(row[1] or 0),
                "severity": prediction_severity(row[1]),
                "key": row[2],
                "value": row[3],
                "details": row[4] or {},
            }
            for row in cur.fetchall()
        ]
        correlations = []
        if has_syslog_correlation_schema(cur):
            cur.execute(
                """
                SELECT c.normalized_iface, c.ifindex, c.evidence, e.ts, e.severity, e.subsystem, e.message
                FROM syslog_interface_correlations c
                JOIN syslog_events e ON e.id = c.syslog_event_id
                WHERE c.asset_id=%s
                  AND e.ts >= %s
                ORDER BY e.ts DESC
                LIMIT 30
                """,
                (host_id, window_start),
            )
            correlations = [
                {
                    "interface": row[0],
                    "ifindex": row[1],
                    "evidence": row[2] or {},
                    "ts": to_iso(row[3]),
                    "severity": row[4],
                    "subsystem": row[5],
                    "message": row[6],
                }
                for row in cur.fetchall()
            ]

    latest_score = max((item["score"] for item in predictions), default=0)
    has_open_loop = any(str(item.get("title") or "").lower().find("loop") >= 0 for item in incidents)
    if has_open_loop or latest_score >= 0.8:
        state = "loop_detectado"
        label = "Loop detectado"
    elif latest_score >= 0.5 or len(correlations) >= 2:
        state = "risco_alto"
        label = "Risco alto"
    elif latest_score >= 0.2 or correlations:
        state = "possivel_risco"
        label = "Possível risco"
    else:
        state = "sem_evidencia"
        label = "Sem evidência"

    return {
        "host_id": host["id"],
        "host_name": host["name"],
        "state": state,
        "label": label,
        "window_minutes": minutes,
        "latest_score": latest_score,
        "incidents": incidents,
        "predictions": predictions,
        "correlations": correlations,
    }

@app.get("/metrics/overview", response_model=Overview)
def metrics_overview():
    """
    Retorna:
      - totais de hosts (ativos/inativos)
      - média global de RTT e perda
      - última métrica (rtt_ms, loss_pct) por host
    Requisitos (ajuste se necessário):
      - Tabela de hosts: {ASSETS_TABLE} (id, name, ip, enabled, ...)
      - Tabela de métricas: {PING_TABLE} com colunas:
            host_id (fk para assets.id)
            ts (timestamp da coleta)
            rtt_ms (float)           -- latência em ms
            loss_pct (float)         -- perda em %
    """
    with get_conn() as conn, conn.cursor() as cur:
        # Resumo de hosts
        cur.execute(
            f"""
            SELECT
                COUNT(*) FILTER (WHERE enabled) AS active,
                COUNT(*) FILTER (WHERE NOT enabled) AS inactive,
                COUNT(*) AS total
            FROM {ASSETS_TABLE};
            """
        )
        row = cur.fetchone()
        active = int(row[0] or 0)
        inactive = int(row[1] or 0)
        total = int(row[2] or 0)

        # Última métrica por host (LEFT JOIN LATERAL)
        # Ajuste nomes das colunas se diferirem no seu banco.
        if has_legacy_ping_schema(cur):
            cur.execute(
                f"""
                SELECT h.id, h.name, h.ip, h.enabled,
                       pm.rtt_ms AS last_rtt_ms,
                       pm.loss_pct AS last_loss_pct
                FROM {ASSETS_TABLE} h
                LEFT JOIN LATERAL (
                    SELECT rtt_ms, loss_pct
                    FROM {PING_TABLE} p
                    WHERE p.host_id = h.id
                    ORDER BY p.ts DESC
                    LIMIT 1
                ) pm ON TRUE
                ORDER BY h.id ASC;
                """
            )
        else:
            cur.execute(
                f"""
                SELECT h.id, h.name, h.ip, h.enabled,
                       rtt.value AS last_rtt_ms,
                       loss.value AS last_loss_pct
                FROM {ASSETS_TABLE} h
                LEFT JOIN LATERAL (
                    SELECT value
                    FROM metrics m
                    WHERE m.asset_id = h.id
                      AND m.metric = 'icmp.rtt_ms'
                    ORDER BY m.ts DESC
                    LIMIT 1
                ) rtt ON TRUE
                LEFT JOIN LATERAL (
                    SELECT value
                    FROM metrics m
                    WHERE m.asset_id = h.id
                      AND m.metric = 'icmp.loss_pct'
                    ORDER BY m.ts DESC
                    LIMIT 1
                ) loss ON TRUE
                ORDER BY h.id ASC;
                """
            )
        rows = cur.fetchall()

    hosts: List[HostRow] = []
    rtt_vals: List[float] = []
    loss_vals: List[float] = []

    for r in rows:
        lrtt = float(r[4]) if r[4] is not None else None
        lloss = float(r[5]) if r[5] is not None else None
        hosts.append(
            HostRow(
                id=r[0],
                name=r[1],
                ip=str(r[2]),
                enabled=bool(r[3]),
                last_rtt_ms=lrtt,
                last_loss_pct=lloss,
            )
        )
        if lrtt is not None:
            rtt_vals.append(lrtt)
        if lloss is not None:
            loss_vals.append(lloss)

    avg_rtt = sum(rtt_vals) / len(rtt_vals) if rtt_vals else None
    avg_loss = sum(loss_vals) / len(loss_vals) if loss_vals else None

    return Overview(
        total_hosts=total,
        active_hosts=active,
        inactive_hosts=inactive,
        avg_rtt_ms=avg_rtt,
        avg_loss_pct=avg_loss,
        hosts=hosts,
    )


@app.get("/capacity/estimate", response_model=CapacityEstimateOut)
def capacity_estimate():
    def env_int(name: str, default: int) -> int:
        try:
            return int(float(os.environ.get(name, str(default))))
        except (TypeError, ValueError):
            return default

    def env_float(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, str(default)))
        except (TypeError, ValueError):
            return default

    sample_bytes = max(1, env_int("CAPACITY_ESTIMATED_SAMPLE_BYTES", 256))
    trend_ratio = max(0.01, min(1.0, env_float("CAPACITY_TREND_RATIO", 0.12)))
    syslog_events_per_host_per_day = max(0.0, env_float("CAPACITY_SYSLOG_EVENTS_PER_HOST_PER_DAY", 20.0))
    incident_events_per_host_per_day = max(0.0, env_float("CAPACITY_INCIDENT_EVENTS_PER_HOST_PER_DAY", 0.25))
    notification_events_per_host_per_day = max(0.0, env_float("CAPACITY_NOTIFICATION_EVENTS_PER_HOST_PER_DAY", 0.35))
    audit_events_per_host_per_day = max(0.0, env_float("CAPACITY_AUDIT_EVENTS_PER_HOST_PER_DAY", 1.0))
    syslog_event_bytes = max(1, env_int("CAPACITY_SYSLOG_EVENT_BYTES", 220))
    incident_event_bytes = max(1, env_int("CAPACITY_INCIDENT_EVENT_BYTES", 512))
    notification_event_bytes = max(1, env_int("CAPACITY_NOTIFICATION_EVENT_BYTES", 420))
    audit_event_bytes = max(1, env_int("CAPACITY_AUDIT_EVENT_BYTES", 384))
    safety_factor = max(1.0, env_float("CAPACITY_DISK_SAFETY_FACTOR", 1.25))
    fallback_items_per_host = max(1.0, env_float("CAPACITY_FALLBACK_ITEMS_PER_HOST", 12.0))

    def capacity_band_label(total_hosts_value: int) -> str:
        if total_hosts_value <= 25:
            return "Ambiente pequeno / laboratório"
        if total_hosts_value <= 100:
            return "Ambiente corporativo pequeno"
        if total_hosts_value <= 250:
            return "Ambiente corporativo médio"
        return "Ambiente mais robusto"

    def hardware_for_hosts(total_hosts_value: int) -> tuple[int, int]:
        if total_hosts_value <= 25:
            return 2, 4
        if total_hosts_value <= 100:
            return 4, 8
        if total_hosts_value <= 250:
            return 6, 16
        return 8, 24

    with get_conn() as conn, conn.cursor() as cur:
        host_rows = list_hosts(limit=5000)

        total_hosts = len(host_rows)
        total_items = 0
        interval_values: list[float] = []
        history_days: list[float] = []
        trend_days: list[float] = []
        log_days: list[float] = []
        incident_days: list[float] = []
        notification_days: list[float] = []
        audit_days: list[float] = []

        if has_monitoring_items_schema(cur):
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total_items,
                    AVG(COALESCE(NULLIF(poll_interval_seconds, 0), 0)) AS avg_interval,
                    AVG(COALESCE(history_retention_days, 30)) AS avg_history,
                    AVG(COALESCE(trend_retention_days, 90)) AS avg_trend,
                    AVG(COALESCE(log_retention_days, 14)) AS avg_log
                FROM monitoring_items
                """
            )
            row = cur.fetchone()
            total_items = int(row[0] or 0)
            avg_interval = float(row[1] or 0) if row[1] is not None else 0.0
            if avg_interval > 0:
                interval_values.append(avg_interval)
            if row[2] is not None:
                history_days.append(float(row[2]))
            if row[3] is not None:
                trend_days.append(float(row[3]))
            if row[4] is not None:
                log_days.append(float(row[4]))

        for host in host_rows:
            policy = host.collection_policy_resolved or {}
            if policy.get("icmp_interval_sec"):
                interval_values.append(float(policy["icmp_interval_sec"]))
            if policy.get("snmp_interval_sec"):
                interval_values.append(float(policy["snmp_interval_sec"]))
            if policy.get("tcp_interval_sec"):
                interval_values.append(float(policy["tcp_interval_sec"]))
            if policy.get("history_retention_days"):
                history_days.append(float(policy["history_retention_days"]))
            if policy.get("trend_retention_days"):
                trend_days.append(float(policy["trend_retention_days"]))
            if policy.get("log_retention_days"):
                log_days.append(float(policy["log_retention_days"]))
            if policy.get("incident_retention_days"):
                incident_days.append(float(policy["incident_retention_days"]))
            if policy.get("notification_retention_days"):
                notification_days.append(float(policy["notification_retention_days"]))
            if policy.get("audit_retention_days"):
                audit_days.append(float(policy["audit_retention_days"]))

        avg_interval_sec = sum(interval_values) / len(interval_values) if interval_values else float(DEFAULT_ICMP_INTERVAL_SEC)
        avg_history_days = sum(history_days) / len(history_days) if history_days else 30.0
        avg_trend_days = sum(trend_days) / len(trend_days) if trend_days else 90.0
        avg_log_days = sum(log_days) / len(log_days) if log_days else 14.0
        avg_incident_days = sum(incident_days) / len(incident_days) if incident_days else 180.0
        avg_notification_days = sum(notification_days) / len(notification_days) if notification_days else 90.0
        avg_audit_days = sum(audit_days) / len(audit_days) if audit_days else 365.0

        avg_items_per_host = total_items / total_hosts if total_hosts else 0.0
        effective_items_per_host = avg_items_per_host if avg_items_per_host > 0 else fallback_items_per_host
        effective_total_items = total_items if total_items > 0 else int(round(total_hosts * effective_items_per_host))
        samples_per_day = 86400.0 / avg_interval_sec if avg_interval_sec > 0 else 0.0
        raw_daily_bytes = int(round(effective_total_items * samples_per_day * sample_bytes))
        trend_daily_bytes = int(round(effective_total_items * samples_per_day * sample_bytes * trend_ratio))
        syslog_daily_bytes = int(round(total_hosts * syslog_events_per_host_per_day * syslog_event_bytes))
        incident_daily_bytes = int(round(total_hosts * incident_events_per_host_per_day * incident_event_bytes))
        notification_daily_bytes = int(round(total_hosts * notification_events_per_host_per_day * notification_event_bytes))
        audit_daily_bytes = int(round(total_hosts * audit_events_per_host_per_day * audit_event_bytes))

        estimated_storage_per_day_bytes = (
            raw_daily_bytes
            + trend_daily_bytes
            + syslog_daily_bytes
            + incident_daily_bytes
            + notification_daily_bytes
            + audit_daily_bytes
        )
        estimated_storage_per_month_bytes = int(round(estimated_storage_per_day_bytes * 30))
        estimated_storage_for_retention_bytes = int(
            round(
                (raw_daily_bytes * avg_history_days)
                + (trend_daily_bytes * avg_trend_days)
                + (syslog_daily_bytes * avg_log_days)
                + (incident_daily_bytes * avg_incident_days)
                + (notification_daily_bytes * avg_notification_days)
                + (audit_daily_bytes * avg_audit_days)
            )
        )
        recommended_disk_bytes = int(round(estimated_storage_for_retention_bytes * safety_factor))

        scenarios: list[dict[str, Any]] = []
        for scenario_hosts in (25, 100, 250, 500):
            scenario_total_items = int(round(scenario_hosts * effective_items_per_host))
            scenario_raw_day = int(round(scenario_total_items * samples_per_day * sample_bytes))
            scenario_trend_day = int(round(scenario_total_items * samples_per_day * sample_bytes * trend_ratio))
            scenario_syslog_day = int(round(scenario_hosts * syslog_events_per_host_per_day * syslog_event_bytes))
            scenario_incident_day = int(round(scenario_hosts * incident_events_per_host_per_day * incident_event_bytes))
            scenario_notification_day = int(round(scenario_hosts * notification_events_per_host_per_day * notification_event_bytes))
            scenario_audit_day = int(round(scenario_hosts * audit_events_per_host_per_day * audit_event_bytes))
            scenario_day_total = (
                scenario_raw_day
                + scenario_trend_day
                + scenario_syslog_day
                + scenario_incident_day
                + scenario_notification_day
                + scenario_audit_day
            )
            scenario_retention_total = int(
                round(
                    (scenario_raw_day * avg_history_days)
                    + (scenario_trend_day * avg_trend_days)
                    + (scenario_syslog_day * avg_log_days)
                    + (scenario_incident_day * avg_incident_days)
                    + (scenario_notification_day * avg_notification_days)
                    + (scenario_audit_day * avg_audit_days)
                )
            )
            scenario_disk = int(round(scenario_retention_total * safety_factor))
            vcpu, ram_gb = hardware_for_hosts(scenario_hosts)
            scenarios.append(
                {
                    "hosts": scenario_hosts,
                    "label": capacity_band_label(scenario_hosts),
                    "estimated_items": scenario_total_items,
                    "estimated_storage_per_day_bytes": scenario_day_total,
                    "estimated_storage_per_month_bytes": int(round(scenario_day_total * 30)),
                    "estimated_storage_for_retention_bytes": scenario_retention_total,
                    "recommended_disk_bytes": scenario_disk,
                    "recommended_vcpu": vcpu,
                    "recommended_ram_gb": ram_gb,
                }
            )

    return CapacityEstimateOut(
        total_hosts=total_hosts,
        total_items=effective_total_items,
        avg_items_per_host=effective_items_per_host,
        avg_collection_interval_sec=avg_interval_sec,
        avg_sample_bytes=sample_bytes,
        avg_history_retention_days=avg_history_days,
        avg_trend_retention_days=avg_trend_days,
        avg_log_retention_days=avg_log_days,
        avg_incident_retention_days=avg_incident_days,
        avg_notification_retention_days=avg_notification_days,
        avg_audit_retention_days=avg_audit_days,
        estimated_storage_per_day_bytes=estimated_storage_per_day_bytes,
        estimated_storage_per_month_bytes=estimated_storage_per_month_bytes,
        estimated_storage_for_retention_bytes=estimated_storage_for_retention_bytes,
        recommended_disk_bytes=recommended_disk_bytes,
        estimated_components={
            "raw_metrics_per_day_bytes": raw_daily_bytes,
            "trend_metrics_per_day_bytes": trend_daily_bytes,
            "syslog_per_day_bytes": syslog_daily_bytes,
            "incidents_per_day_bytes": incident_daily_bytes,
            "notifications_per_day_bytes": notification_daily_bytes,
            "audit_per_day_bytes": audit_daily_bytes,
        },
        scenarios=scenarios,
        assumptions={
            "sample_bytes": sample_bytes,
            "trend_ratio": trend_ratio,
            "fallback_items_per_host": fallback_items_per_host,
            "syslog_events_per_host_per_day": syslog_events_per_host_per_day,
            "incident_events_per_host_per_day": incident_events_per_host_per_day,
            "notification_events_per_host_per_day": notification_events_per_host_per_day,
            "audit_events_per_host_per_day": audit_events_per_host_per_day,
            "syslog_event_bytes": syslog_event_bytes,
            "incident_event_bytes": incident_event_bytes,
            "notification_event_bytes": notification_event_bytes,
            "audit_event_bytes": audit_event_bytes,
            "safety_factor": safety_factor,
            "is_estimate": True,
        },
        formula=(
            "metricas_dia = hosts * itens_por_host * (86400 / intervalo_medio_segundos) * bytes_por_amostra; "
            "trends_dia = metricas_dia * fator_trends; "
            "syslog_dia = hosts * eventos_syslog_dia * bytes_syslog; "
            "incidentes_dia = hosts * incidentes_dia * bytes_incidente; "
            "notificacoes_dia = hosts * notificacoes_dia * bytes_notificacao; "
            "auditoria_dia = hosts * eventos_auditoria_dia * bytes_auditoria; "
            "retencao_total = soma(componente_dia * dias_de_retencao_do_componente)"
        ),
    )

@app.get("/incidents", response_model=List[IncidentOut])
def list_incidents(
    asset_id: Optional[int] = None,
    host_id: Optional[int] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    q: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 200,
):
    normalized_asset_id = asset_id if asset_id is not None else host_id

    with get_conn() as conn, conn.cursor() as cur:
        records = select_incident_records(
            cur,
            asset_id=normalized_asset_id,
            group_id=group_id,
            template_id=template_id,
            status=status,
            severity=severity,
            incident_type=incident_type,
            q=q,
            from_ts=parse_datetime_filter(from_ts),
            to_ts=parse_datetime_filter(to_ts, end_of_day=True),
            limit=limit,
        )

    return [IncidentOut(**record) for record in records]


ALERT_CHANNEL_SENSITIVE_FIELDS = {
    "email": {"smtp_password"},
    "discord": {"webhook_url"},
    "telegram": {"bot_token"},
    "slack": {"webhook_url"},
    "msteams": {"webhook_url"},
    "google_chat": {"webhook_url"},
    "mattermost": {"webhook_url"},
    "rocketchat": {"webhook_url"},
    "pushover": {"app_token", "user_key"},
    "webhook": {"webhook_url", "headers"},
}
ALERT_CHANNEL_PROVIDER_SQL = ", ".join(f"'{provider}'" for provider in sorted(ALERT_CHANNEL_PROVIDERS))
ALERT_CHANNEL_WEBHOOK_PROVIDERS = {"discord", "slack", "msteams", "google_chat", "mattermost", "rocketchat", "webhook"}


def ensure_alerts_schema(cur) -> None:
    cur.execute("SELECT to_regclass('incidents')")
    if cur.fetchone()[0] is None:
        raise HTTPException(status_code=503, detail="A tabela de incidentes ainda nao foi inicializada no banco.")

    cur.execute(
        """
        ALTER TABLE incidents
          ADD COLUMN IF NOT EXISTS device_name text,
          ADD COLUMN IF NOT EXISTS device_ip inet,
          ADD COLUMN IF NOT EXISTS problem_type text,
          ADD COLUMN IF NOT EXISTS description text,
          ADD COLUMN IF NOT EXISTS first_detected_at timestamptz,
          ADD COLUMN IF NOT EXISTS last_detected_at timestamptz,
          ADD COLUMN IF NOT EXISTS resolved_at timestamptz,
          ADD COLUMN IF NOT EXISTS notification_sent boolean default false,
          ADD COLUMN IF NOT EXISTS opening_notification_sent boolean default false,
          ADD COLUMN IF NOT EXISTS recovery_notification_sent boolean default false,
          ADD COLUMN IF NOT EXISTS opening_notified_at timestamptz,
          ADD COLUMN IF NOT EXISTS recovery_notified_at timestamptz,
          ADD COLUMN IF NOT EXISTS last_notification_at timestamptz,
          ADD COLUMN IF NOT EXISTS notification_fingerprint text,
          ADD COLUMN IF NOT EXISTS created_at timestamptz default now(),
          ADD COLUMN IF NOT EXISTS updated_at timestamptz default now()
        """
    )
    cur.execute(
        """
        UPDATE incidents
        SET
          device_name = COALESCE(device_name, hostname),
          device_ip = COALESCE(device_ip, src_ip),
          problem_type = COALESCE(problem_type, upper(incident_type)),
          description = COALESCE(description, title),
          first_detected_at = COALESCE(first_detected_at, opened_at),
          last_detected_at = GREATEST(
            COALESCE(last_detected_at, '-infinity'::timestamptz),
            COALESCE(last_seen_at, '-infinity'::timestamptz),
            COALESCE(opened_at, '-infinity'::timestamptz)
          ),
          resolved_at = CASE
            WHEN resolved_at IS NULL AND LOWER(status) IN ('resolved', 'closed') THEN last_seen_at
            ELSE resolved_at
          END,
          created_at = COALESCE(created_at, opened_at, now()),
          updated_at = GREATEST(
            COALESCE(updated_at, '-infinity'::timestamptz),
            COALESCE(last_detected_at, '-infinity'::timestamptz),
            COALESCE(last_seen_at, '-infinity'::timestamptz),
            COALESCE(opened_at, '-infinity'::timestamptz)
          ),
          notification_sent = COALESCE(notification_sent, false)
        WHERE
          device_name IS NULL
          OR device_ip IS NULL
          OR problem_type IS NULL
          OR description IS NULL
          OR first_detected_at IS NULL
          OR last_detected_at IS NULL
          OR created_at IS NULL
          OR updated_at IS NULL
          OR notification_sent IS NULL
          OR (
            LOWER(status) IN ('resolved', 'closed')
            AND resolved_at IS NULL
          )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_notifications (
          id bigserial primary key,
          incident_id bigint references incidents(id) on delete cascade,
          channel text not null,
          provider text,
          delivery_status text not null,
          error text,
          sent_at timestamptz not null default now()
        )
        """
    )
    cur.execute(
        """
        WITH first_success AS (
          SELECT incident_id, MIN(sent_at) AS sent_at
          FROM incident_notifications
          WHERE LOWER(COALESCE(delivery_status, '')) = 'success'
            AND LOWER(COALESCE(provider, '')) <> 'anti_spam'
          GROUP BY incident_id
        ),
        recovery_success AS (
          SELECT i.id AS incident_id, MIN(n.sent_at) AS sent_at
          FROM incidents i
          JOIN incident_notifications n ON n.incident_id = i.id
          WHERE i.resolved_at IS NOT NULL
            AND n.sent_at >= i.resolved_at
            AND LOWER(COALESCE(n.delivery_status, '')) = 'success'
            AND LOWER(COALESCE(n.provider, '')) <> 'anti_spam'
          GROUP BY i.id
        ),
        lifecycle AS (
          SELECT
            i.id,
            first_success.sent_at AS opening_success_at,
            recovery_success.sent_at AS recovery_success_at
          FROM incidents i
          LEFT JOIN first_success ON first_success.incident_id = i.id
          LEFT JOIN recovery_success ON recovery_success.incident_id = i.id
        )
        UPDATE incidents i
        SET
          opening_notification_sent = COALESCE(i.opening_notification_sent, false)
            OR COALESCE(i.notification_sent, false)
            OR lifecycle.opening_success_at IS NOT NULL,
          opening_notified_at = COALESCE(i.opening_notified_at, lifecycle.opening_success_at),
          recovery_notification_sent = COALESCE(i.recovery_notification_sent, false)
            OR lifecycle.recovery_success_at IS NOT NULL,
          recovery_notified_at = COALESCE(i.recovery_notified_at, lifecycle.recovery_success_at),
          last_notification_at = NULLIF(GREATEST(
            COALESCE(i.last_notification_at, '-infinity'::timestamptz),
            COALESCE(i.opening_notified_at, '-infinity'::timestamptz),
            COALESCE(lifecycle.opening_success_at, '-infinity'::timestamptz),
            COALESCE(i.recovery_notified_at, '-infinity'::timestamptz),
            COALESCE(lifecycle.recovery_success_at, '-infinity'::timestamptz)
          ), '-infinity'::timestamptz),
          notification_fingerprint = COALESCE(
            NULLIF(i.notification_fingerprint, ''),
            NULLIF(i.details->>'notification_fingerprint', ''),
            NULLIF(i.details->>'loop_fingerprint', ''),
            CONCAT_WS('|',
              split_part(COALESCE(i.device_ip::text, i.src_ip::text, ''), '/', 1),
              UPPER(COALESCE(i.problem_type, i.incident_type, '')),
              COALESCE(
                NULLIF(i.details->>'interface_pair', ''),
                NULLIF(i.details->>'affected_context', ''),
                NULLIF(i.details->>'ifName', ''),
                NULLIF(i.details->>'item', ''),
                'host'
              )
            )
          ),
          notification_sent = COALESCE(i.notification_sent, false)
            OR COALESCE(i.opening_notification_sent, false)
            OR lifecycle.opening_success_at IS NOT NULL
        FROM lifecycle
        WHERE
          i.id = lifecycle.id
          AND (
            lifecycle.opening_success_at IS NOT NULL
            OR lifecycle.recovery_success_at IS NOT NULL
            OR i.opening_notification_sent IS NULL
            OR i.recovery_notification_sent IS NULL
            OR i.notification_fingerprint IS NULL
          )
        """
    )
    cur.execute(
        """
        ALTER TABLE incidents
          ALTER COLUMN notification_sent SET DEFAULT false,
          ALTER COLUMN notification_sent SET NOT NULL,
          ALTER COLUMN opening_notification_sent SET DEFAULT false,
          ALTER COLUMN opening_notification_sent SET NOT NULL,
          ALTER COLUMN recovery_notification_sent SET DEFAULT false,
          ALTER COLUMN recovery_notification_sent SET NOT NULL,
          ALTER COLUMN created_at SET DEFAULT now(),
          ALTER COLUMN created_at SET NOT NULL,
          ALTER COLUMN updated_at SET DEFAULT now(),
          ALTER COLUMN updated_at SET NOT NULL
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_notifications (
          id bigserial primary key,
          incident_id bigint references incidents(id) on delete cascade,
          channel text not null,
          provider text,
          delivery_status text not null,
          error text,
          sent_at timestamptz not null default now()
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_incidents_alert_open_dedupe
          ON incidents (device_ip, problem_type, status, last_detected_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_incidents_alert_activity
          ON incidents (updated_at DESC, last_detected_at DESC, id DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_incidents_notification_lifecycle
          ON incidents (status, notification_sent, recovery_notification_sent, resolved_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_incidents_notification_fingerprint
          ON incidents (notification_fingerprint, last_notification_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_incident_notifications_incident_sent
          ON incident_notifications (incident_id, sent_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_incident_notifications_status_sent
          ON incident_notifications (delivery_status, sent_at DESC)
        """
    )


def ensure_alert_channels_schema(cur) -> None:
    ensure_alerts_schema(cur)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_channels (
          id bigserial primary key,
          name text not null,
          provider text not null,
          enabled boolean not null default true,
          min_severity text not null default 'LOW',
          config jsonb not null default '{}'::jsonb,
          last_test_status text,
          last_test_error text,
          last_test_at timestamptz,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now()
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_alert_channels_enabled_provider
          ON alert_channels (enabled, provider, min_severity)
        """
    )
    cur.execute(
        f"""
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'ck_alert_channels_provider'
              AND pg_get_constraintdef(oid) NOT LIKE '%slack%'
          ) THEN
            ALTER TABLE alert_channels
              DROP CONSTRAINT ck_alert_channels_provider;
          END IF;

          IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'ck_alert_channels_provider'
          ) THEN
            ALTER TABLE alert_channels
              ADD CONSTRAINT ck_alert_channels_provider
              CHECK (provider in ({ALERT_CHANNEL_PROVIDER_SQL}));
          END IF;
        END $$;
        """
    )


@app.on_event("startup")
def ensure_alert_notification_lifecycle_schema() -> None:
    try:
        with get_conn() as conn, conn.cursor() as cur:
            ensure_alert_channels_schema(cur)
            conn.commit()
    except Exception:
        return


def normalize_alert_provider(value: str) -> str:
    provider = str(value or "").strip().lower()
    if provider not in ALERT_CHANNEL_PROVIDERS:
        allowed = ", ".join(sorted(ALERT_CHANNEL_PROVIDERS))
        raise HTTPException(status_code=400, detail=f"provider must be one of {allowed}")
    return provider


def normalize_alert_min_severity(value: str) -> str:
    severity = str(value or "LOW").strip().upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="min_severity must be LOW, MEDIUM, HIGH or CRITICAL")
    return severity


def merge_message_template_config(normalized: dict[str, Any], incoming: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    for key in ("problem_template", "recovery_template", "problem_title_template", "recovery_title_template"):
        normalized[key] = str(incoming.get(key, previous.get(key, "")) or "")
    return normalized


def alert_display_severity(value: Any) -> str:
    normalized = str(value or "LOW").strip().upper()
    legacy_map = {
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "NOTICE": "LOW",
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
        "ERROR": "HIGH",
        "ERR": "HIGH",
        "FATAL": "CRITICAL",
        "DISASTER": "CRITICAL",
    }
    return legacy_map.get(normalized, normalized if normalized in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "LOW")


def alert_display_status(value: Any) -> str:
    normalized = str(value or "OPEN").strip().upper()
    if normalized in {"CLOSED", "CLOSE"}:
        return "RESOLVED"
    if normalized in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        return normalized
    return normalized or "OPEN"


ALERT_ACTIVITY_SQL = """
GREATEST(
  COALESCE(i.updated_at, '-infinity'::timestamptz),
  COALESCE(i.last_detected_at, '-infinity'::timestamptz),
  COALESCE(i.last_seen_at, '-infinity'::timestamptz),
  COALESCE(i.opened_at, '-infinity'::timestamptz)
)
"""


def is_masked_secret(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text == "********" or "***" in text


def normalize_channel_config(provider: str, config: dict[str, Any], existing: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    provider = normalize_alert_provider(provider)
    incoming = dict(config or {})
    previous = dict(existing or {})
    normalized: dict[str, Any] = {}

    if provider == "email":
        for key in ("smtp_host", "smtp_user", "smtp_from", "alert_email_to"):
            normalized[key] = str(incoming.get(key, previous.get(key, "")) or "").strip()
        try:
            normalized["smtp_port"] = int(incoming.get("smtp_port", previous.get("smtp_port", 587)) or 587)
        except (TypeError, ValueError):
            normalized["smtp_port"] = 587
        normalized["use_tls"] = bool(incoming.get("use_tls", previous.get("use_tls", True)))
        password = incoming.get("smtp_password")
        if existing is not None and is_masked_secret(password):
            normalized["smtp_password"] = str(previous.get("smtp_password") or "")
        else:
            normalized["smtp_password"] = str(password or "")
        return merge_message_template_config(normalized, incoming, previous)

    if provider == "discord":
        return normalize_webhook_channel_config(provider, incoming, previous, existing)

    if provider in ALERT_CHANNEL_WEBHOOK_PROVIDERS:
        return normalize_webhook_channel_config(provider, incoming, previous, existing)

    if provider == "pushover":
        app_token = incoming.get("app_token")
        user_key = incoming.get("user_key")
        if existing is not None and is_masked_secret(app_token):
            app_token = previous.get("app_token")
        if existing is not None and is_masked_secret(user_key):
            user_key = previous.get("user_key")
        normalized = {
            "app_token": str(app_token or "").strip(),
            "user_key": str(user_key or "").strip(),
            "device": str(incoming.get("device", previous.get("device", "")) or "").strip(),
            "sound": str(incoming.get("sound", previous.get("sound", "")) or "").strip(),
        }
        try:
            normalized["priority"] = int(incoming.get("priority", previous.get("priority", 0)) or 0)
        except (TypeError, ValueError):
            normalized["priority"] = 0
        return merge_message_template_config(normalized, incoming, previous)

    if provider == "telegram":
        bot_token = incoming.get("bot_token")
        if existing is not None and is_masked_secret(bot_token):
            bot_token = previous.get("bot_token")
        normalized = {
            "bot_token": str(bot_token or "").strip(),
            "chat_id": str(incoming.get("chat_id", previous.get("chat_id", "")) or "").strip(),
            "parse_mode": str(incoming.get("parse_mode", previous.get("parse_mode", "")) or "").strip(),
        }
        return merge_message_template_config(normalized, incoming, previous)

    return normalize_webhook_channel_config(provider, incoming, previous, existing)


def normalize_webhook_channel_config(provider: str, incoming: dict[str, Any], previous: dict[str, Any], existing: Optional[dict[str, Any]]) -> dict[str, Any]:
    provider = normalize_alert_provider(provider)
    webhook_url = incoming.get("webhook_url")
    if existing is not None and is_masked_secret(webhook_url):
        webhook_url = previous.get("webhook_url")
    normalized = {"webhook_url": str(webhook_url or "").strip()}
    if provider == "mattermost":
        normalized["username"] = str(incoming.get("username", previous.get("username", "NetGuard")) or "NetGuard").strip()
    if provider == "rocketchat":
        normalized["alias"] = str(incoming.get("alias", previous.get("alias", "NetGuard")) or "NetGuard").strip()
    if provider == "webhook":
        headers = incoming.get("headers", previous.get("headers", {}))
        if isinstance(headers, dict):
            previous_headers = previous.get("headers", {}) if isinstance(previous.get("headers"), dict) else {}
            normalized["headers"] = {
                str(key): str(previous_headers.get(key) if existing is not None and is_masked_secret(value) else value)
                for key, value in headers.items()
            }
        else:
            normalized["headers"] = {}
    return merge_message_template_config(normalized, incoming, previous)


def mask_secret(value: Any, *, prefix: int = 0) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if prefix and len(text) > prefix:
        return f"{text[:prefix]}***"
    return "********"


def mask_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/***"
    return "********"


def mask_channel_config(provider: str, config: dict[str, Any]) -> dict[str, Any]:
    provider = normalize_alert_provider(provider)
    masked = dict(config or {})
    if provider == "email" and masked.get("smtp_password"):
        masked["smtp_password"] = "********"
    if provider in ALERT_CHANNEL_WEBHOOK_PROVIDERS and masked.get("webhook_url"):
        if provider == "discord":
            masked["webhook_url"] = "https://discord.com/api/webhooks/***"
        else:
            masked["webhook_url"] = mask_url(masked.get("webhook_url"))
    if provider == "telegram" and masked.get("bot_token"):
        masked["bot_token"] = mask_secret(masked.get("bot_token"), prefix=7)
    if provider == "pushover":
        if masked.get("app_token"):
            masked["app_token"] = mask_secret(masked.get("app_token"), prefix=6)
        if masked.get("user_key"):
            masked["user_key"] = mask_secret(masked.get("user_key"), prefix=6)
    if provider == "webhook" and isinstance(masked.get("headers"), dict):
        masked["headers"] = {key: "********" for key in masked["headers"]}
    return masked


def alert_channel_out_from_row(row) -> dict[str, Any]:
    return {
        "id": row[0],
        "name": row[1],
        "provider": row[2],
        "enabled": bool(row[3]),
        "min_severity": normalize_alert_min_severity(row[4]),
        "config": mask_channel_config(row[2], row[5] or {}),
        "last_test_status": row[6],
        "last_test_error": row[7],
        "last_test_at": to_iso(row[8]),
        "created_at": to_iso(row[9]),
        "updated_at": to_iso(row[10]),
    }


def get_alert_channel_raw(cur, channel_id: int) -> dict[str, Any]:
    cur.execute(
        """
        SELECT id, name, provider, enabled, min_severity, config,
               last_test_status, last_test_error, last_test_at, created_at, updated_at
        FROM alert_channels
        WHERE id = %s
        """,
        (channel_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Canal de alerta não encontrado.")
    return {
        "id": row[0],
        "name": row[1],
        "provider": row[2],
        "enabled": bool(row[3]),
        "min_severity": row[4],
        "config": row[5] or {},
        "last_test_status": row[6],
        "last_test_error": row[7],
        "last_test_at": row[8],
        "created_at": row[9],
        "updated_at": row[10],
        "_row": row,
    }


def notification_out_from_row(row) -> dict[str, Any]:
    return {
        "id": row[0],
        "incident_id": row[1],
        "channel": row[2],
        "provider": row[3],
        "delivery_status": row[4],
        "error": row[5],
        "sent_at": to_iso(row[6]) or "",
    }


@app.get("/alerts/notifications", response_model=List[AlertNotificationOut])
def list_alert_notifications(
    incident_id: Optional[int] = None,
    provider: Optional[str] = None,
    delivery_status: Optional[str] = None,
    limit: int = 100,
):
    query = """
        SELECT id, incident_id, channel, provider, delivery_status, error, sent_at
        FROM incident_notifications
    """
    conditions: list[str] = []
    params: list[Any] = []

    if incident_id is not None:
        conditions.append("incident_id = %s")
        params.append(incident_id)
    if provider:
        conditions.append("LOWER(provider) = LOWER(%s)")
        params.append(provider)
    if delivery_status:
        conditions.append("LOWER(delivery_status) = LOWER(%s)")
        params.append(delivery_status)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY sent_at DESC, id DESC LIMIT %s"
    params.append(normalize_limit(limit, default=100, maximum=1000))

    with get_conn() as conn, conn.cursor() as cur:
        ensure_alerts_schema(cur)
        cur.execute(query, params)
        return [AlertNotificationOut(**notification_out_from_row(row)) for row in cur.fetchall()]


@app.get("/alerts/incidents", response_model=List[AlertIncidentOut])
def list_alert_incidents(limit: int = 100):
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alerts_schema(cur)
        cur.execute(
            f"""
            SELECT
              i.id,
              COALESCE(i.device_name, i.hostname) AS device_name,
              COALESCE(split_part(i.device_ip::text, '/', 1), split_part(i.src_ip::text, '/', 1)) AS device_ip,
              COALESCE(i.problem_type, upper(i.incident_type)) AS problem_type,
              COALESCE(i.description, i.title) AS description,
              i.severity,
              i.status,
              COALESCE(i.first_detected_at, i.opened_at) AS first_detected_at,
              GREATEST(
                COALESCE(i.last_detected_at, '-infinity'::timestamptz),
                COALESCE(i.last_seen_at, '-infinity'::timestamptz),
                COALESCE(i.opened_at, '-infinity'::timestamptz)
              ) AS last_detected_at,
              i.resolved_at,
              i.notification_sent,
              i.details,
              {ALERT_ACTIVITY_SQL} AS activity_at,
              n.id,
              n.channel,
              n.provider,
              n.delivery_status,
              n.error,
              n.sent_at
            FROM incidents i
            LEFT JOIN LATERAL (
              SELECT id, channel, provider, delivery_status, error, sent_at
              FROM incident_notifications
              WHERE incident_id = i.id
              ORDER BY sent_at DESC, id DESC
              LIMIT 1
            ) n ON true
            ORDER BY activity_at DESC, i.id DESC
            LIMIT %s
            """,
            (normalize_limit(limit, default=100, maximum=1000),),
        )
        records = []
        for row in cur.fetchall():
            latest_notification = None
            details = row[11] or {}
            if row[13] is not None:
                latest_notification = {
                    "id": row[13],
                    "channel": row[14],
                    "provider": row[15],
                    "delivery_status": row[16],
                    "error": row[17],
                    "sent_at": to_iso(row[18]),
                }
            records.append(
                AlertIncidentOut(
                    id=row[0],
                    device_name=row[1] or "",
                    device_ip=row[2] or "",
                    problem_type=row[3] or "",
                    description=row[4] or "",
                    severity=alert_display_severity(row[5]),
                    status=alert_display_status(row[6]),
                    first_detected_at=to_iso(row[7]),
                    last_detected_at=to_iso(row[8]),
                    resolved_at=to_iso(row[9]),
                    notification_sent=bool(row[10]),
                    updated_at=to_iso(row[12]),
                    latest_notification=latest_notification,
                    resolution_source=details.get("resolution_source") or details.get("recovery_source"),
                    recovery_evidence=details.get("recovery_evidence") or details.get("recovery_reason"),
                )
            )
        return records


@app.get("/alerts/summary", response_model=AlertSummaryOut)
def get_alert_summary():
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        cur.execute(
            """
            SELECT
              COUNT(*) FILTER (WHERE LOWER(COALESCE(status, '')) IN ('open', 'acknowledged')) AS open_alerts,
              COUNT(*) FILTER (
                WHERE LOWER(COALESCE(status, '')) IN ('open', 'acknowledged')
                  AND LOWER(COALESCE(severity, '')) = 'critical'
              ) AS critical_open_alerts
            FROM incidents
            """
        )
        open_alerts, critical_open_alerts = cur.fetchone()

        cur.execute(
            """
            SELECT
              COUNT(*) FILTER (WHERE LOWER(delivery_status) = 'success') AS sent_today,
              COUNT(*) FILTER (WHERE LOWER(provider) = 'anti_spam' OR LOWER(delivery_status) = 'suppressed') AS suppressed_today
            FROM incident_notifications
            WHERE sent_at >= date_trunc('day', now())
            """
        )
        sent_today, suppressed_today = cur.fetchone()

        cur.execute("SELECT COUNT(*) FROM alert_channels WHERE enabled = true")
        active_channels = cur.fetchone()[0]

        cur.execute(
            f"""
            SELECT
              id,
              COALESCE(device_name, hostname) AS device_name,
              COALESCE(device_ip::text, src_ip::text) AS device_ip,
              COALESCE(problem_type, upper(incident_type)) AS problem_type,
              severity,
              status,
              {ALERT_ACTIVITY_SQL} AS activity_at
            FROM incidents i
            ORDER BY activity_at DESC, id DESC
            LIMIT 1
            """
        )
        last_row = cur.fetchone()

    last_alert = None
    if last_row is not None:
        last_alert = {
            "id": last_row[0],
            "device_name": last_row[1],
            "device_ip": str(last_row[2] or "").split("/")[0],
            "problem_type": last_row[3],
            "severity": alert_display_severity(last_row[4]),
            "status": alert_display_status(last_row[5]),
            "updated_at": to_iso(last_row[6]),
        }

    return AlertSummaryOut(
        open_alerts=int(open_alerts or 0),
        critical_open_alerts=int(critical_open_alerts or 0),
        notifications_sent_today=int(sent_today or 0),
        notifications_suppressed_today=int(suppressed_today or 0),
        active_channels=int(active_channels or 0),
        last_alert=last_alert,
    )


@app.get("/alerts/channels", response_model=List[AlertChannelOut])
def list_alert_channels():
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        cur.execute(
            """
            SELECT id, name, provider, enabled, min_severity, config,
                   last_test_status, last_test_error, last_test_at, created_at, updated_at
            FROM alert_channels
            ORDER BY enabled DESC, name, id
            """
        )
        return [AlertChannelOut(**alert_channel_out_from_row(row)) for row in cur.fetchall()]


@app.post("/alerts/channels", response_model=AlertChannelOut)
def create_alert_channel(payload: AlertChannelIn):
    provider = normalize_alert_provider(payload.provider)
    min_severity = normalize_alert_min_severity(payload.min_severity)
    config = normalize_channel_config(provider, payload.config)

    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        cur.execute(
            """
            INSERT INTO alert_channels (name, provider, enabled, min_severity, config)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, name, provider, enabled, min_severity, config,
                      last_test_status, last_test_error, last_test_at, created_at, updated_at
            """,
            (
                payload.name.strip(),
                provider,
                bool(payload.enabled),
                min_severity,
                psycopg.types.json.Json(config),
            ),
        )
        row = cur.fetchone()

    return AlertChannelOut(**alert_channel_out_from_row(row))


@app.put("/alerts/channels/{channel_id}", response_model=AlertChannelOut)
def update_alert_channel(channel_id: int, payload: AlertChannelIn):
    provider = normalize_alert_provider(payload.provider)
    min_severity = normalize_alert_min_severity(payload.min_severity)

    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        existing = get_alert_channel_raw(cur, channel_id)
        existing_config = existing["config"] if existing["provider"] == provider else None
        config = normalize_channel_config(provider, payload.config, existing_config)
        cur.execute(
            """
            UPDATE alert_channels
            SET name = %s,
                provider = %s,
                enabled = %s,
                min_severity = %s,
                config = %s,
                updated_at = now()
            WHERE id = %s
            RETURNING id, name, provider, enabled, min_severity, config,
                      last_test_status, last_test_error, last_test_at, created_at, updated_at
            """,
            (
                payload.name.strip(),
                provider,
                bool(payload.enabled),
                min_severity,
                psycopg.types.json.Json(config),
                channel_id,
            ),
        )
        row = cur.fetchone()

    return AlertChannelOut(**alert_channel_out_from_row(row))


@app.patch("/alerts/channels/{channel_id}/toggle", response_model=AlertChannelOut)
def toggle_alert_channel(channel_id: int, payload: AlertChannelToggleIn):
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        cur.execute(
            """
            UPDATE alert_channels
            SET enabled = %s,
                updated_at = now()
            WHERE id = %s
            RETURNING id, name, provider, enabled, min_severity, config,
                      last_test_status, last_test_error, last_test_at, created_at, updated_at
            """,
            (bool(payload.enabled), channel_id),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Canal de alerta não encontrado.")

    return AlertChannelOut(**alert_channel_out_from_row(row))


@app.delete("/alerts/channels/{channel_id}")
def delete_alert_channel(channel_id: int):
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        cur.execute("DELETE FROM alert_channels WHERE id = %s RETURNING id", (channel_id,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Canal de alerta não encontrado.")
    return {"ok": True}


@app.post("/alerts/channels/{channel_id}/test", response_model=AlertChannelTestOut)
def test_alert_channel(channel_id: int):
    sent_at = datetime.now(timezone.utc)
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        channel = get_alert_channel_raw(cur, channel_id)
        alert_channel = AlertChannel(
            id=channel["id"],
            name=channel["name"],
            provider=channel["provider"],
            enabled=channel["enabled"],
            min_severity=channel["min_severity"],
            config=channel["config"],
        )
        result = build_alert_service(cur).test_channel(alert_channel)
        cur.execute(
            """
            UPDATE alert_channels
            SET last_test_status = %s,
                last_test_error = %s,
                last_test_at = %s,
                updated_at = now()
            WHERE id = %s
            """,
            (result.status, result.error, sent_at, channel_id),
        )
        PostgresIncidentRepository(cur, assets_table=ASSETS_TABLE).record_notification_result(None, result, sent_at)

    return AlertChannelTestOut(
        channel_id=channel_id,
        channel=result.channel,
        provider=result.provider or alert_channel.provider,
        delivery_status=result.status,
        error=result.error,
        sent_at=to_iso(sent_at) or "",
    )


def process_alert_problem(payload: AlertProblemIn) -> AlertResultOut:
    problem = AlertProblem(
        device_name=payload.device_name,
        device_ip=str(payload.device_ip),
        problem_type=payload.problem_type,
        description=payload.description,
        severity=payload.severity,
        details=payload.details,
        detected_at=payload.detected_at,
    )

    try:
        with get_conn() as conn, conn.cursor() as cur:
            ensure_alert_channels_schema(cur)
            result = build_alert_service(cur).handle_problem(problem)
            return AlertResultOut(**result.to_dict())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/alerts", response_model=AlertResultOut)
def create_alert(payload: AlertProblemIn):
    return process_alert_problem(payload)


@app.post("/alerts/test", response_model=AlertResultOut)
def test_alert(payload: AlertProblemIn):
    return process_alert_problem(payload)


@app.post("/alerts/incidents/{incident_id}/notify", response_model=AlertResultOut)
def notify_alert_incident(incident_id: int, payload: Optional[AlertNotifyIn] = None):
    request = payload or AlertNotifyIn()
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        result = build_alert_service(cur).notify_incident(incident_id, force=request.force)

    if result is None:
        raise HTTPException(status_code=404, detail="Incidente não encontrado.")

    return AlertResultOut(**result.to_dict())


def resolve_alert_problem(
    incident_id: int,
    payload: Optional[AlertResolveIn] = None,
    http_request: Optional[Request] = None,
) -> AlertResultOut:
    resolve_request = payload or AlertResolveIn()
    actor = request_user(http_request) if isinstance(http_request, Request) else None
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        if resolve_request.manual_reason or resolve_request.resolution_source:
            source = resolve_request.resolution_source or "manual"
            details_patch = {
                "resolution_source": source,
                "resolved_by": actor.get("email") if actor else "operator",
                "resolved_by_name": actor.get("name") if actor else "Operador",
                "manual_resolution_reason": resolve_request.manual_reason or "",
            }
            cur.execute(
                """
                UPDATE incidents
                SET details = COALESCE(details, '{}'::jsonb) || %s::jsonb,
                    updated_at = now()
                WHERE id = %s
                """,
                (json.dumps(details_patch, ensure_ascii=False), incident_id),
            )
        result = build_alert_service(cur).resolve_incident(
            incident_id,
            send_recovery_notification=resolve_request.send_recovery_notification,
        )

    if result is None:
        raise HTTPException(status_code=404, detail="Incidente n\u00e3o encontrado.")

    return AlertResultOut(**result.to_dict())


@app.post("/alerts/incidents/{incident_id}/resolve", response_model=AlertResultOut)
def resolve_alert_incident(incident_id: int, request: Request, payload: Optional[AlertResolveIn] = None):
    return resolve_alert_problem(incident_id, payload, request)


@app.post("/incidents/{incident_id}/resolve", response_model=AlertResultOut)
def resolve_incident(incident_id: int, request: Request, payload: Optional[AlertResolveIn] = None):
    return resolve_alert_problem(incident_id, payload, request)


@app.post("/alerts/incidents/{incident_id}/acknowledge")
def acknowledge_alert_incident(
    incident_id: int,
    request: Request,
    payload: Optional[AlertAcknowledgeIn] = None,
):
    actor = request_user(request) if isinstance(request, Request) else None
    note = (payload.note if payload else None) or ""
    details_patch = {
        "acknowledged_by": actor.get("email") if actor else "operator",
        "acknowledged_by_name": actor.get("name") if actor else "Operador",
        "acknowledged_at": datetime.now(timezone.utc).isoformat(),
        "acknowledgement_note": note,
    }
    with get_conn() as conn, conn.cursor() as cur:
        ensure_alert_channels_schema(cur)
        cur.execute(
            """
            UPDATE incidents
            SET status = 'acknowledged',
                details = COALESCE(details, '{}'::jsonb) || %s::jsonb,
                updated_at = now()
            WHERE id = %s
              AND LOWER(COALESCE(status, '')) = 'open'
            RETURNING id, status, details
            """,
            (json.dumps(details_patch, ensure_ascii=False), incident_id),
        )
        row = cur.fetchone()
        if row is None:
            cur.execute("SELECT id, status, details FROM incidents WHERE id = %s", (incident_id,))
            row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Incidente nao encontrado.")
    return {
        "incident_id": row[0],
        "status": alert_display_status(row[1]),
        "details": row[2] or {},
    }


@app.get("/hosts/{host_id}/incidents", response_model=List[IncidentOut])
def list_host_incidents(
    host_id: int,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 200,
):
    with get_conn() as conn, conn.cursor() as cur:
        host = get_host_record(cur, host_id)
        records = select_incident_records(
            cur,
            host_record=host,
            status=status,
            severity=severity,
            incident_type=incident_type,
            from_ts=parse_datetime_filter(from_ts),
            to_ts=parse_datetime_filter(to_ts, end_of_day=True),
            limit=limit,
        )

    return [IncidentOut(**record) for record in records]


@app.get("/hosts/{host_id}/syslog", response_model=List[SyslogEventOut])
def list_host_syslog(
    host_id: int,
    severity: Optional[str] = None,
    subsystem: Optional[str] = None,
    q: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 100,
):
    with get_conn() as conn, conn.cursor() as cur:
        host = get_host_record(cur, host_id)
        records = select_syslog_records(
            cur,
            host_record=host,
            severity=severity,
            subsystem=subsystem,
            q=q,
            from_ts=parse_datetime_filter(from_ts),
            to_ts=parse_datetime_filter(to_ts, end_of_day=True),
            limit=limit,
        )

    return [SyslogEventOut(**record) for record in records]


@app.get("/hosts/{host_id}/predictions", response_model=HostPredictionsOut)
def list_host_predictions(
    host_id: int,
    metric: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 100,
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)

    with get_conn() as conn, conn.cursor() as cur:
        host = get_host_record(cur, host_id)
        loop_risk_incidents = select_incident_records(
            cur,
            host_record=host,
            incident_type="loop_risk",
            from_ts=parsed_from,
            to_ts=parsed_to,
            limit=limit,
        )
        anomaly_scores = select_prediction_records(
            cur,
            asset_id=host_id,
            metric=metric,
            from_ts=parsed_from,
            to_ts=parsed_to,
            limit=limit,
        )

    prediction_items = [
        PredictionOut(
            ts=item["ts"],
            asset_id=item["asset_id"],
            metric=item["metric"],
            key=item["key"],
            score=item["score"],
            severity=item["severity"],
            z=item["z"],
            value=item["value"],
            baseline_mean=item["baseline_mean"],
            baseline_std=item["baseline_std"],
            details=item["details"],
        )
        for item in anomaly_scores
    ]

    max_score = max((item.score for item in prediction_items), default=None)
    latest_ts = prediction_items[0].ts if prediction_items else None
    loop_risk_open = sum(
        1 for item in loop_risk_incidents if normalize_status_value(item["status"]) == "open"
    )

    return HostPredictionsOut(
        host_id=host_id,
        host_name=host["name"],
        summary=PredictionsSummaryOut(
            anomaly_count=len(prediction_items),
            max_score=max_score,
            latest_ts=latest_ts,
            loop_risk_open=loop_risk_open,
            loop_risk_total=len(loop_risk_incidents),
        ),
        loop_risk_incidents=[IncidentOut(**item) for item in loop_risk_incidents],
        anomaly_scores=prediction_items,
    )

def select_metric_records(
    cur,
    *,
    asset_id: Optional[int] = None,
    metric: Optional[str] = None,
    metric_prefix: Optional[str] = None,
    from_ts=None,
    to_ts=None,
    limit: int = 200,
):
    query = """
        SELECT ts, asset_id, metric, value, labels
        FROM metrics
    """
    conditions: list[str] = []
    params: list[Any] = []

    if asset_id is not None:
        conditions.append("asset_id = %s")
        params.append(asset_id)

    if metric is not None:
        conditions.append("metric = %s")
        params.append(metric)

    if metric_prefix:
        conditions.append("metric LIKE %s")
        params.append(f"{metric_prefix}%")

    append_time_conditions(conditions, params, "ts", from_ts, to_ts)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY ts DESC LIMIT %s"
    params.append(normalize_limit(limit, default=200, maximum=5000))
    cur.execute(query, params)

    return [
        MetricOut(
            ts=to_iso(r[0]) or "",
            asset_id=r[1],
            metric=r[2],
            value=float(r[3]),
            labels=r[4] or {},
        )
        for r in cur.fetchall()
    ]


def list_host_profile_records(cur, host_id: int) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT
            mp.id,
            mp.name,
            mp.display_name,
            mp.kind,
            mp.description,
            mp.config,
            ap.params,
            ap.enabled
        FROM asset_profiles ap
        JOIN monitoring_profiles mp ON mp.id = ap.profile_id
        WHERE ap.asset_id = %s
        ORDER BY mp.display_name, mp.name
        """,
        (host_id,),
    )
    rows = cur.fetchall()

    return [
        {
            "profile_id": row[0],
            "name": row[1],
            "display_name": row[2] or row[1],
            "kind": row[3],
            "description": row[4],
            "config": row[5] or {},
            "params": row[6] or {},
            "enabled": bool(row[7]),
        }
        for row in rows
    ]


def get_incident_record(cur, incident_id: int) -> dict[str, Any]:
    query = """
        SELECT
            i.id,
            i.opened_at,
            i.last_seen_at,
            i.status,
            i.hostname,
            i.src_ip,
            i.incident_type,
            i.key,
            i.severity,
            i.title,
            i.details,
            i.asset_id,
            a.group_id,
            g.name,
            g.path,
            a.template_id,
            t.name
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.asset_id
        LEFT JOIN host_groups g ON g.id = a.group_id
        LEFT JOIN monitoring_templates t ON t.id = a.template_id
        WHERE i.id = %s
    """
    cur.execute(query, (incident_id,))
    row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Incidente não encontrado.")

    return incident_output_from_row(row)


def ai_insight_title(insight_type: str) -> str:
    meta = AI_INSIGHT_TYPE_META.get(str(insight_type).strip().lower(), {})
    return meta.get("label", str(insight_type or "Insight"))


def ai_insight_ttl_hours(insight_type: str) -> int:
    meta = AI_INSIGHT_TYPE_META.get(str(insight_type).strip().lower(), {})
    return int(meta.get("ttl_hours", AI_INSIGHTS_TTL_HOURS))


def ai_insight_row_to_dict(row) -> dict[str, Any]:
    return {
        "id": row[0],
        "target_type": row[1],
        "target_id": int(row[2] or 0),
        "insight_type": row[3],
        "status": row[4],
        "model": row[5],
        "title": ai_insight_title(row[3]),
        "content_md": row[6] or "",
        "content_json": row[7] or {},
        "evidence_json": row[8] or {},
        "created_at": to_iso(row[9]) or "",
        "expires_at": to_iso(row[10]),
        "cached": False,
    }


def get_cached_ai_insight_record(cur, *, target_type: str, target_id: int, insight_type: str) -> Optional[dict[str, Any]]:
    cur.execute(
        """
        SELECT
            id,
            target_type,
            target_id,
            insight_type,
            status,
            model,
            content_md,
            content_json,
            evidence_json,
            created_at,
            expires_at
        FROM ai_insights
        WHERE target_type = %s
          AND target_id = %s
          AND insight_type = %s
          AND status = 'ready'
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (target_type, int(target_id), insight_type),
    )
    row = cur.fetchone()
    if row is None:
        return None
    record = ai_insight_row_to_dict(row)
    evidence = record.get("evidence_json") or {}
    if int(evidence.get("context_version") or 0) != AI_CONTEXT_VERSION:
        return None
    return record


def list_ai_insight_records(
    cur,
    *,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    insight_type: Optional[str] = None,
    include_expired: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]]:
    query = """
        SELECT
            id,
            target_type,
            target_id,
            insight_type,
            status,
            model,
            content_md,
            content_json,
            evidence_json,
            created_at,
            expires_at
        FROM ai_insights
    """
    conditions: list[str] = []
    params: list[Any] = []

    if target_type:
        conditions.append("target_type = %s")
        params.append(str(target_type).strip().lower())

    if target_id is not None:
        conditions.append("target_id = %s")
        params.append(int(target_id))

    if insight_type:
        conditions.append("insight_type = %s")
        params.append(str(insight_type).strip().lower())

    if not include_expired:
        conditions.append("(expires_at IS NULL OR expires_at > NOW())")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY created_at DESC, id DESC LIMIT %s"
    params.append(normalize_limit(limit, default=50, maximum=500))
    cur.execute(query, params)
    return [ai_insight_row_to_dict(row) for row in cur.fetchall()]


def store_ai_insight_record(
    cur,
    *,
    target_type: str,
    target_id: int,
    insight_type: str,
    model: str,
    content_md: str,
    content_json: dict[str, Any],
    evidence_json: dict[str, Any],
    expires_at,
) -> dict[str, Any]:
    cur.execute(
        """
        INSERT INTO ai_insights (
            target_type,
            target_id,
            insight_type,
            status,
            model,
            content_md,
            content_json,
            evidence_json,
            expires_at
        )
        VALUES (%s, %s, %s, 'ready', %s, %s, %s, %s, %s)
        RETURNING
            id,
            target_type,
            target_id,
            insight_type,
            status,
            model,
            content_md,
            content_json,
            evidence_json,
            created_at,
            expires_at
        """,
        (
            target_type,
            int(target_id),
            insight_type,
            model,
            content_md,
            psycopg.types.json.Json(content_json or {}),
            psycopg.types.json.Json(evidence_json or {}),
            expires_at,
        ),
    )
    return ai_insight_row_to_dict(cur.fetchone())


HOST_AI_INTERFACE_TOKEN_REGEX = (
    r"(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Port-channel|Ethernet|Loopback|Vlan|Te|Gi|Fa|Po|Eth|Lo)"
    r"\d+(?:/\d+)*(?:\.\d+)?"
)
HOST_AI_INTERFACE_TOKEN_PATTERN = re.compile(HOST_AI_INTERFACE_TOKEN_REGEX, re.IGNORECASE)
HOST_AI_INTERFACE_PAIR_PATTERN = re.compile(
    rf"({HOST_AI_INTERFACE_TOKEN_REGEX})\s*<->\s*({HOST_AI_INTERFACE_TOKEN_REGEX})",
    re.IGNORECASE,
)
HOST_AI_SIGNAL_LABELS = {
    "interface_flap": "Flap de interface",
    "loop_storm": "Loop ou storm",
    "mac_flap": "MAC flapping",
    "link_trap": "Trap linkUp/linkDown",
    "other": "Syslog",
}
HOST_AI_SIGNAL_ORDER = ("loop_storm", "mac_flap", "interface_flap", "link_trap")
INCIDENT_SIGNAL_LABELS = {
    "BROADCAST_STORM": "Broadcast storm",
    "STP_DISABLED": "STP desabilitado",
    "STP_TOPOLOGY_CHANGE": "Mudanca de topologia STP",
    "MAC_FLAPPING": "MAC flapping",
    "MAC_FLAP": "MAC flapping",
    "INTERFACE_FLAP": "Interface flap",
    "LINK_TRAP": "Trap linkUp/linkDown",
    "LINKUP": "Trap linkUp/linkDown",
    "LINKDOWN": "Trap linkUp/linkDown",
}


def normalize_incident_signal_name(value: Optional[str]) -> str:
    text = re.sub(r"[^A-Z0-9]+", "_", str(value or "").upper()).strip("_")
    return text


def incident_signal_category(value: Optional[str]) -> str:
    normalized = normalize_incident_signal_name(value)
    if (
        normalized in {"BROADCAST_STORM", "STP_DISABLED", "STP_TOPOLOGY_CHANGE"}
        or "LOOP" in normalized
        or "STORM" in normalized
        or normalized.startswith("STP_")
    ):
        return "loop_storm"
    if normalized in {"MAC_FLAPPING", "MAC_FLAP", "MAC_MOVE"} or normalized.startswith("MAC_"):
        return "mac_flap"
    if (
        normalized in {"INTERFACE_FLAP", "PORT_FLAP", "LINK_FLAP"}
        or "FLAP" in normalized
        or "UPDOWN" in normalized
    ):
        return "interface_flap"
    if normalized in {"LINK_TRAP", "LINKUP", "LINKDOWN"} or normalized.startswith("TRAP_LINK"):
        return "link_trap"
    return "other"


def incident_signal_priority(value: Optional[str]) -> int:
    return {
        "loop_storm": 0,
        "mac_flap": 1,
        "interface_flap": 2,
        "link_trap": 3,
        "other": 8,
    }.get(incident_signal_category(value), 8)


def incident_signal_label(value: Optional[str], fallback: Optional[str] = None) -> str:
    normalized = normalize_incident_signal_name(value)
    if normalized in INCIDENT_SIGNAL_LABELS:
        return INCIDENT_SIGNAL_LABELS[normalized]
    category = incident_signal_category(normalized)
    if category == "loop_storm":
        return "Loop ou storm"
    if category == "mac_flap":
        return "MAC flapping"
    if category == "interface_flap":
        return "Interface flap"
    if category == "link_trap":
        return "Trap linkUp/linkDown"
    return str(fallback or normalized or "Sinal")


INCIDENT_TYPE_LABELS = {
    "host_down": "Host indisponível",
    "snmp_collection_silence": "Sem telemetria SNMP recente",
    "icmp_collection_silence": "Sem telemetria ICMP recente",
    "syslog_collection_silence": "Sem eventos syslog recentes",
    "loop_risk": "Risco de loop L2",
    "broadcast_storm": "Broadcast storm",
    "mac_flapping": "MAC flapping",
    "interface_flap": "Interface oscilando",
}


def incident_type_label(value: Optional[str], title: Optional[str] = None) -> str:
    title_text = str(title or "").strip()
    if title_text and not title_text.lower().startswith("[netguard]"):
        return title_text
    normalized = str(value or "").strip().lower()
    return INCIDENT_TYPE_LABELS.get(normalized, normalized.replace("_", " ").strip().title() or "Incidente")


def incident_type_default_impact(incident_type: Optional[str], fallback: str = "") -> str:
    normalized = str(incident_type or "").strip().lower()
    generic = {
        "",
        "-",
        "sem evidências de impacto operacional relevante no momento.",
        "sem impacto operacional relevante definido.",
    }
    fallback_text = str(fallback or "").strip()
    if fallback_text.lower() not in generic:
        return fallback_text
    defaults = {
        "snmp_collection_silence": "O host ainda pode estar acessível, mas inventário, interfaces, counters e telemetria SNMP podem ficar desatualizados até a coleta voltar.",
        "icmp_collection_silence": "A disponibilidade por ICMP fica incerta; o host pode estar ativo por outros protocolos, mas o NetGuard perdeu a confirmação básica de alcance.",
        "host_down": "O ativo pode estar indisponível ou sem alcance ICMP/SNMP; serviços dependentes podem ficar degradados até confirmar energia, uplink, VLAN/gateway e ACL/firewall.",
        "loop_risk": "O segmento L2 afetado pode degradar ou ficar indisponível se houver storm, MAC flapping ou encaminhamento indevido.",
    }
    return defaults.get(normalized, fallback_text or "Sem impacto operacional relevante definido.")


def prioritize_incident_signal_contexts(
    signal_contexts: list[dict[str, Any]],
    *,
    limit: int = 6,
) -> list[dict[str, Any]]:
    prioritized = list(signal_contexts or [])
    prioritized.sort(
        key=lambda item: (
            incident_signal_priority(item.get("signal")),
            -int(item.get("count") or 0),
            -ai_timestamp_epoch(item.get("last_seen_at") or item.get("first_seen_at")),
            str(item.get("focus") or ""),
        )
    )
    return prioritized[:limit]


def parse_incident_evidence_token(value: Any) -> Optional[dict[str, str]]:
    raw_text = str(value or "").strip()
    if not raw_text:
        return None
    signal_text, separator, focus_text = raw_text.partition(":")
    signal = normalize_incident_signal_name(signal_text)
    if not signal:
        return None
    focus = normalize_interface_name(focus_text) if separator else None
    normalized_focus = focus or str(focus_text or "").strip() or None
    return {
        "signal": signal,
        "focus": normalized_focus or "host",
    }


def normalize_interface_name(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None

    text = re.sub(r"^[<>\[(]+", "", text)
    text = re.sub(r"[>\]),.;:]+$", "", text)
    replacements = (
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("Port-channel", "Po"),
        ("Ethernet", "Eth"),
        ("Loopback", "Lo"),
        ("Vlan", "Vlan"),
    )
    lowered = text.lower()
    for prefix, short in replacements:
        if lowered.startswith(prefix.lower()):
            return short + text[len(prefix) :]
    return text


SYSLOG_PROCESS_EVENT_PATTERN = re.compile(
    r"^%?(?P<subsystem>[A-Za-z][A-Za-z0-9_]*)(?:-(?P<level>[0-7])-(?P<code>[A-Za-z0-9_]+))?$"
)
SYSLOG_LEVEL_TO_SEVERITY = {
    "0": "critical",
    "1": "critical",
    "2": "high",
    "3": "high",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "info",
}
SYSLOG_SUBSYSTEM_KEYWORDS: list[tuple[str, str]] = [
    ("LOOPGUARD", "spantree"),
    ("SPANTREE", "spantree"),
    ("TOPOLOGY CHANGE", "spantree"),
    ("TCN", "spantree"),
    ("MACFLAP", "sw_matm"),
    ("MAC FLAP", "sw_matm"),
    ("MAC FLAPPING", "sw_matm"),
    ("SW_MATM", "sw_matm"),
    ("STORMCTRL", "stormctrl"),
    ("BROADCAST STORM", "stormctrl"),
    ("STORM CONTROL", "stormctrl"),
    ("LINE PROTOCOL ON INTERFACE", "lineproto"),
    ("CHANGED STATE TO", "link"),
    ("ERR_DISABLE", "pm"),
    ("ERR-RECOVER", "pm"),
    ("PORTAS:", "system"),
    ("CONFIGURAÇÃO SALVA", "system"),
    ("CONFIG:", "system"),
    ("INICIADO", "system"),
    ("TESTE DE SYSLOG MANUAL", "manual"),
    ("BURST DE ERROS", "counters"),
    ("DISCARD", "counters"),
    ("COUNTERS", "counters"),
    ("LOOP", "loop"),
]


def normalize_syslog_subsystem(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    text = text.lstrip("%").rstrip(":")
    if "-" in text and text.upper() == text:
        proc_match = SYSLOG_PROCESS_EVENT_PATTERN.match(text)
        if proc_match:
            text = proc_match.group("subsystem")
    return normalize_status_value(text.replace(" ", "_"))


def infer_syslog_severity(
    severity: Optional[str],
    process: Optional[str],
    message: Optional[str],
    raw: Optional[str],
) -> Optional[str]:
    upper_text = " ".join(str(part or "").upper() for part in (process, message, raw))
    normalized = normalize_severity_value(severity)
    if normalized:
        if normalized.isdigit():
            return SYSLOG_LEVEL_TO_SEVERITY.get(normalized)
        return normalized

    if "CHANGED STATE TO UP" in upper_text:
        return "notice"
    if "CHANGED STATE TO DOWN" in upper_text:
        return "warning"

    process_match = SYSLOG_PROCESS_EVENT_PATTERN.match(str(process or "").strip().rstrip(":"))
    if process_match and process_match.group("level"):
        return SYSLOG_LEVEL_TO_SEVERITY.get(process_match.group("level"))

    if any(token in upper_text for token in ("UNPROTECTED", "ERR_DISABLE", "LOOP DETECTADO")):
        return "high"
    if any(
        token in upper_text
        for token in (
            "LOOPGUARD_BLOCK",
            "BROADCAST STORM",
            "STORMCTRL",
            "MACFLAP",
            "MAC FLAP",
            "BURST DE ERROS",
            "CHANGED STATE TO DOWN",
        )
    ):
        return "warning"
    if any(token in upper_text for token in ("TOPOTRAP", "DESABILITADO", "CHANGED STATE TO UP")):
        return "notice"
    if any(token in upper_text for token in ("TESTE DE SYSLOG MANUAL", "INICIADO", "CONFIGURAÇÃO SALVA", "PORTAS:")):
        return "info"
    return None


def infer_syslog_subsystem(
    subsystem: Optional[str],
    process: Optional[str],
    message: Optional[str],
    raw: Optional[str],
) -> Optional[str]:
    normalized = normalize_syslog_subsystem(subsystem)
    if normalized:
        return normalized

    process_text = str(process or "").strip().lstrip("%").rstrip(":")
    proc_match = SYSLOG_PROCESS_EVENT_PATTERN.match(process_text)
    if proc_match:
        return normalize_syslog_subsystem(proc_match.group("subsystem"))

    upper_text = " ".join(str(part or "").upper() for part in (process, message, raw))
    for token, mapped in SYSLOG_SUBSYSTEM_KEYWORDS:
        if token in upper_text:
            return mapped
    return None


def enrich_syslog_event_fields(
    *,
    process: Optional[str],
    severity: Optional[str],
    subsystem: Optional[str],
    iface: Optional[str],
    message: Optional[str],
    raw: Optional[str],
) -> dict[str, Optional[str]]:
    resolved_iface = normalize_interface_name(iface)
    pair = extract_interface_pair_from_text(iface, message, raw)
    if pair:
        resolved_iface = pair["label"]
    elif not resolved_iface:
        interfaces = extract_interface_names_from_text(iface, message, raw)
        if len(interfaces) == 1:
            resolved_iface = interfaces[0]

    return {
        "severity": infer_syslog_severity(severity, process, message, raw),
        "subsystem": infer_syslog_subsystem(subsystem, process, message, raw),
        "iface": resolved_iface,
    }


def extract_interface_pair_from_text(*parts: Optional[str]) -> Optional[dict[str, str]]:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        match = HOST_AI_INTERFACE_PAIR_PATTERN.search(text)
        if not match:
            continue
        left = normalize_interface_name(match.group(1))
        right = normalize_interface_name(match.group(2))
        if left and right:
            return {
                "left": left,
                "right": right,
                "label": f"{left}<->{right}",
            }
    return None


def extract_interface_names_from_text(*parts: Optional[str]) -> list[str]:
    seen: set[str] = set()
    interfaces: list[str] = []
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        for token in HOST_AI_INTERFACE_TOKEN_PATTERN.findall(text):
            normalized = normalize_interface_name(token)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            interfaces.append(normalized)
    return interfaces


def classify_host_signal(message: Optional[str]) -> str:
    upper_message = str(message or "").upper()

    if "SNMP TRAP" in upper_message and ("LINKDOWN" in upper_message or "LINKUP" in upper_message):
        return "link_trap"
    if any(token in upper_message for token in ("MACFLAP", "MAC FLAP", "MAC_FLAPPING", "MAC MOVE")):
        return "mac_flap"
    if any(token in upper_message for token in ("LOOP", "STORM", "SPANTREE", "TOPOLOGY CHANGE", "TCN")):
        return "loop_storm"
    if any(
        token in upper_message
        for token in (
            "LINEPROTO",
            "LINE PROTOCOL",
            "UPDOWN",
            "FLAPPED",
            "INTERFACE_FLAP",
            "LINKDOWN",
            "LINKUP",
            "CHANGED STATE TO DOWN",
            "CHANGED STATE TO UP",
        )
    ):
        return "interface_flap"
    return "other"


def prioritize_compact_syslog_for_ai(events: list[dict[str, Any]], *, limit: int = 12) -> list[dict[str, Any]]:
    signal_priority = {
        "loop_storm": 0,
        "mac_flap": 1,
        "interface_flap": 2,
        "link_trap": 3,
        "other": 4,
    }
    per_signal_limits = {
        "loop_storm": 4,
        "mac_flap": 4,
        "interface_flap": 4,
        "link_trap": 4,
        "other": 2,
    }

    def event_sort_key(item: dict[str, Any]) -> tuple[int, str]:
        signal_type = str(item.get("signal_type") or "other")
        return (
            signal_priority.get(signal_type, 9),
            str(item.get("ts") or ""),
        )

    ordered = sorted(events, key=event_sort_key, reverse=False)
    ordered = sorted(ordered, key=lambda item: str(item.get("ts") or ""), reverse=True)

    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    selected_per_signal: dict[str, int] = {}
    for item in sorted(
        ordered,
        key=lambda event: (
            signal_priority.get(str(event.get("signal_type") or "other"), 9),
            -len(str(event.get("interfaces") or [])),
            -len(str(event.get("message") or "")),
        ),
    ):
        signal_type = str(item.get("signal_type") or "other")
        if selected_per_signal.get(signal_type, 0) >= per_signal_limits.get(signal_type, 2):
            continue
        focus = str(
            item.get("interface_pair")
            or item.get("iface")
            or next(iter(item.get("interfaces") or []), "host")
        )
        message = str(item.get("message") or "").strip()
        dedupe_key = (signal_type, focus, message)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        selected.append(item)
        selected_per_signal[signal_type] = selected_per_signal.get(signal_type, 0) + 1
        if len(selected) >= limit:
            break

    return selected


def summarize_signal_group(signal_type: str, focus: str, count: int) -> str:
    target = focus if focus and focus != "host" else "o host"
    if signal_type == "loop_storm":
        return f"Sinal de loop ou broadcast storm em {target}"
    if signal_type == "mac_flap":
        return f"MAC flapping detectado em {target}"
    if signal_type == "interface_flap":
        prefix = "Flap recorrente" if count > 1 else "Flap detectado"
        return f"{prefix} na {target}" if target != "o host" else f"{prefix} no host"
    if signal_type == "link_trap":
        return f"Trap SNMP linkUp/linkDown associado a {target}" if target != "o host" else "Trap SNMP linkUp/linkDown observado no host"
    return f"Sinal operacional observado em {target}"


def parse_ai_timestamp(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_host_signal_groups(
    syslog_events: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped_buckets: dict[str, dict[str, dict[str, Any]]] = {
        signal_type: {} for signal_type in HOST_AI_SIGNAL_ORDER
    }
    flap_candidates: list[dict[str, Any]] = []

    for event in syslog_events:
        if str(event.get("signal_type") or "") != "interface_flap":
            continue
        focus = event.get("iface") or next(iter(event.get("interfaces") or []), None)
        if not focus:
            continue
        flap_candidates.append(
            {
                "iface": str(focus),
                "ts": parse_ai_timestamp(event.get("ts")),
            }
        )

    for event in syslog_events:
        signal_type = str(event.get("signal_type") or "other")
        if signal_type not in grouped_buckets:
            continue
        if host_signal_event_is_recovery(event):
            continue

        interface_pair = event.get("interface_pair")
        interfaces = list(event.get("interfaces") or [])
        focus = None
        if interface_pair:
            focus = interface_pair
        elif event.get("iface"):
            focus = event.get("iface")
        elif interfaces:
            focus = interfaces[0]

        if signal_type == "link_trap" and not focus:
            event_ts = parse_ai_timestamp(event.get("ts"))
            if event_ts is not None:
                for candidate in flap_candidates:
                    candidate_ts = candidate.get("ts")
                    if candidate_ts is None:
                        continue
                    if abs((event_ts - candidate_ts).total_seconds()) <= 6:
                        focus = candidate.get("iface")
                        break

        focus = (
            focus
            or "host"
        )
        bucket_key = f"{signal_type}:{focus}"
        bucket = grouped_buckets[signal_type].get(bucket_key)
        if bucket is None:
            bucket = {
                "signal_type": signal_type,
                "signal_label": HOST_AI_SIGNAL_LABELS.get(signal_type, "Syslog"),
                "focus": focus,
                "interfaces": interfaces,
                "interface_pair": interface_pair,
                "count": 0,
                "first_seen": event.get("ts"),
                "last_seen": event.get("ts"),
                "messages": [],
            }
            grouped_buckets[signal_type][bucket_key] = bucket

        bucket["count"] += 1
        ts = event.get("ts")
        if ts and (bucket.get("first_seen") is None or str(ts) < str(bucket["first_seen"])):
            bucket["first_seen"] = ts
        if ts and (bucket.get("last_seen") is None or str(ts) > str(bucket["last_seen"])):
            bucket["last_seen"] = ts
        message = str(event.get("message") or "").strip()
        if message and message not in bucket["messages"] and len(bucket["messages"]) < 3:
            bucket["messages"].append(message)

    prediction_highlights: list[dict[str, Any]] = []
    for item in predictions:
        signal_counts = item.get("signal_counts") if isinstance(item.get("signal_counts"), dict) else {}
        if signal_counts:
            prediction_highlights.append(
                {
                    "metric": item.get("metric"),
                    "severity": item.get("severity"),
                    "score": item.get("score"),
                    "signal_counts": signal_counts,
                    "snmp_hints": trim_ai_items(item.get("snmp_hints") or [], 4),
                    "recommendation": item.get("recommendation"),
                }
            )

    grouped_output: dict[str, list[dict[str, Any]]] = {}
    for signal_type in HOST_AI_SIGNAL_ORDER:
        items = list(grouped_buckets[signal_type].values())
        items.sort(
            key=lambda item: (
                str(item.get("last_seen") or ""),
                int(item.get("count") or 0),
            ),
            reverse=True,
        )
        grouped_output[signal_type] = [
            {
                **item,
                "summary": summarize_signal_group(
                    signal_type,
                    str(item.get("focus") or "host"),
                    int(item.get("count") or 0),
                ),
            }
            for item in items[:4]
        ]

    if prediction_highlights:
        grouped_output["prediction_highlights"] = prediction_highlights[:3]

    return grouped_output


def format_host_signal_group_for_prompt(item: dict[str, Any]) -> str:
    signal_type = str(item.get("signal_type") or "")
    focus = str(item.get("focus") or "host")
    count = int(item.get("count") or 0)
    messages = item.get("messages") or []
    sample = f" Exemplo: {messages[0]}" if messages else ""

    if signal_type == "loop_storm":
        return f"Loop ou broadcast storm em {focus} ({count} evento(s)).{sample}"
    if signal_type == "mac_flap":
        return f"MAC flapping em {focus} ({count} evento(s)).{sample}"
    if signal_type == "interface_flap":
        return f"Flap recorrente em {focus} ({count} evento(s)).{sample}"
    if signal_type == "link_trap":
        return f"Trap linkUp/linkDown associado a {focus} ({count} evento(s)).{sample}"
    return f"Sinal operacional em {focus} ({count} evento(s)).{sample}"


AI_ACTIVE_INCIDENT_STATUSES = {"open", "acknowledged"}
AI_RECENT_SIGNAL_WINDOW_SECONDS = 15 * 60
AI_MIN_RELEVANT_PREDICTION_SCORE = 0.20


def ai_incident_is_active(incident: dict[str, Any]) -> bool:
    status = normalize_status_value(incident.get("status"))
    if status in AI_ACTIVE_INCIDENT_STATUSES:
        return True
    if status:
        return False
    return incident.get("resolved_at") is None


def ai_prediction_score(prediction: dict[str, Any]) -> float:
    try:
        return float(prediction.get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def ai_prediction_is_relevant(prediction: dict[str, Any], *, low_signal: bool = False) -> bool:
    metric = str(prediction.get("metric") or "").strip().lower()
    if metric == "loop_risk":
        return True
    score = ai_prediction_score(prediction)
    severity = str(prediction.get("severity") or "").strip().lower()
    if score <= 0:
        return False
    if low_signal:
        return severity_rank(severity) <= severity_rank("info") and score < AI_MIN_RELEVANT_PREDICTION_SCORE
    return severity_rank(severity) > severity_rank("info") or score >= AI_MIN_RELEVANT_PREDICTION_SCORE


def ai_context_reference_ts(context: dict[str, Any]) -> Optional[datetime]:
    window = context.get("time_window") if isinstance(context.get("time_window"), dict) else {}
    return parse_ai_timestamp(window.get("to")) or datetime.now(timezone.utc)


def ai_item_is_current(ts_value: Any, context: dict[str, Any], *, max_age_seconds: int = AI_RECENT_SIGNAL_WINDOW_SECONDS) -> bool:
    item_ts = parse_ai_timestamp(ts_value)
    reference_ts = ai_context_reference_ts(context)
    if item_ts is None or reference_ts is None:
        return False
    return (reference_ts - item_ts).total_seconds() <= max_age_seconds


def host_signal_event_is_recovery(event: dict[str, Any]) -> bool:
    text = " ".join(
        str(part or "")
        for part in (event.get("message"), event.get("raw"), event.get("subsystem"))
    ).lower()
    recovery_terms = (
        "cleared",
        "clear",
        "resolved",
        "recovered",
        "recovery",
        "recuperado",
        "normalizado",
        "normalizou",
        "limpo",
        "limpos",
        "cessou",
    )
    return any(term in text for term in recovery_terms)


def build_host_findings_summary(context: dict[str, Any]) -> dict[str, list[str] | Optional[str]]:
    host = context.get("host") or {}
    active_incidents = [item for item in list(context.get("active_incidents") or []) if ai_incident_is_active(item)]
    recent_incidents = list(context.get("recent_incidents") or [])
    signal_groups = context.get("signal_groups") or {}
    predictions = list(context.get("recent_predictions") or [])

    primary_issue = None
    problems: list[str] = []
    supporting: list[str] = []
    historical: list[str] = []

    if active_incidents:
        incident = active_incidents[0]
        primary_issue = (
            f"Incidente {incident.get('incident_type') or 'operacional'} "
            f"{incident.get('severity') or 'sem severidade'} aberto para o host"
        )
        if incident.get("title"):
            primary_issue = f"{primary_issue}: {incident.get('title')}"
    elif recent_incidents:
        latest = recent_incidents[0]
        status = normalize_status_value(latest.get("status")) or "desconhecido"
        if status in {"resolved", "closed"}:
            historical.append(
                f"Historico recente: incidente {latest.get('incident_type') or 'operacional'} "
                f"{latest.get('severity') or 'sem severidade'} esta {status}."
            )

    for signal_type in HOST_AI_SIGNAL_ORDER:
        for item in signal_groups.get(signal_type) or []:
            line = format_host_signal_group_for_prompt(item)
            is_current = ai_item_is_current(item.get("last_seen"), context)
            if signal_type == "link_trap":
                supporting.append(line)
            elif active_incidents or is_current:
                problems.append(line)
            else:
                historical.append(f"Historico recente fora da janela atual: {line}")

    l2_risk_present = bool(
        any(str(item.get("incident_type") or "").strip().lower() == "loop_risk" for item in active_incidents)
        or any(ai_item_is_current(item.get("last_seen"), context) for item in signal_groups.get("loop_storm") or [])
        or any(ai_item_is_current(item.get("last_seen"), context) for item in signal_groups.get("mac_flap") or [])
    )

    for prediction in predictions:
        metric = str(prediction.get("metric") or "").lower()
        if metric == "loop_risk":
            continue
        if not ai_prediction_is_relevant(prediction):
            continue
        if_name = prediction.get("if_name")
        location = f" em {if_name}" if if_name else ""
        severity = prediction.get("severity") or "sem severidade"
        score_pct = int(round(ai_prediction_score(prediction) * 100))
        line = f"Anomalia SNMP {prediction.get('metric')}{location} com severidade {severity} e score {score_pct}%."
        if l2_risk_present and severity_rank(severity) <= severity_rank("info"):
            supporting.append(line)
        else:
            problems.append(line)

    deduped_problems: list[str] = []
    seen_problems: set[str] = set()
    for item in problems:
        normalized = item.strip()
        if not normalized or normalized in seen_problems:
            continue
        seen_problems.add(normalized)
        deduped_problems.append(normalized)

    deduped_supporting: list[str] = []
    seen_supporting: set[str] = set()
    for item in supporting:
        normalized = item.strip()
        if not normalized or normalized in seen_supporting:
            continue
        seen_supporting.add(normalized)
        deduped_supporting.append(normalized)

    deduped_historical: list[str] = []
    seen_historical: set[str] = set()
    for item in historical:
        normalized = item.strip()
        if not normalized or normalized in seen_historical:
            continue
        seen_historical.add(normalized)
        deduped_historical.append(normalized)

    if primary_issue is None and deduped_problems:
        primary_issue = deduped_problems[0]

    return {
        "primary_issue": primary_issue,
        "problems": deduped_problems[:8],
        "supporting_signals": deduped_supporting[:6],
        "historical_signals": deduped_historical[:6],
        "health_status": str(host.get("health_status") or "-"),
        "operational_posture": str(host.get("operational_posture") or "-"),
    }


def dedupe_text_items(items: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = str(item or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def metric_value_to_float(metric: dict[str, Any]) -> Optional[float]:
    try:
        return float(metric.get("value"))
    except (TypeError, ValueError):
        return None


def build_runbook_entries(keys: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in keys:
        normalized = str(key or "").strip().lower()
        if not normalized or normalized in seen or normalized not in MINIMAL_OPERATIONAL_RUNBOOKS:
            continue
        seen.add(normalized)
        meta = MINIMAL_OPERATIONAL_RUNBOOKS[normalized]
        entries.append(
            {
                "key": normalized,
                "title": meta["title"],
                "actions": list(meta["actions"]),
            }
        )
    return entries


def build_host_operational_assessment(context: dict[str, Any]) -> dict[str, Any]:
    host = context.get("host") or {}
    active_incidents = [item for item in list(context.get("active_incidents") or []) if ai_incident_is_active(item)]
    recent_incidents = list(context.get("recent_incidents") or [])
    signal_groups = context.get("signal_groups") or {}
    predictions = list(context.get("recent_predictions") or [])
    latest_metrics = list(context.get("latest_metrics") or [])
    recent_syslog = list(context.get("recent_syslog") or [])

    loop_incident = next(
        (
            item
            for item in active_incidents
            if str(item.get("incident_type") or "").strip().lower() == "loop_risk"
        ),
        None,
    )
    loop_prediction = next(
        (
            item
            for item in predictions
            if str(item.get("metric") or "").strip().lower() == "loop_risk"
            and ai_prediction_score(item) >= 0.5
            and ai_item_is_current(item.get("ts"), context)
        ),
        None,
    )
    all_loop_groups = list(signal_groups.get("loop_storm") or [])
    all_mac_groups = list(signal_groups.get("mac_flap") or [])
    all_flap_groups = list(signal_groups.get("interface_flap") or [])
    loop_groups = [item for item in all_loop_groups if ai_item_is_current(item.get("last_seen"), context)]
    mac_groups = [item for item in all_mac_groups if ai_item_is_current(item.get("last_seen"), context)]
    flap_groups = [item for item in all_flap_groups if ai_item_is_current(item.get("last_seen"), context)]
    historical_loop_groups = [item for item in all_loop_groups if item not in loop_groups]
    historical_mac_groups = [item for item in all_mac_groups if item not in mac_groups]
    historical_flap_groups = [item for item in all_flap_groups if item not in flap_groups]
    trap_groups = list(signal_groups.get("link_trap") or [])
    loop_signal_contexts = list(loop_incident.get("signal_contexts") or []) if loop_incident else []

    facts: list[str] = []
    secondary: list[str] = []
    supporting: list[str] = []
    inferences: list[str] = []
    limits: list[str] = []
    runbook_keys: list[str] = []

    state = "Sem sinais operacionais relevantes no período analisado."
    impact = "Sem evidências de impacto operacional relevante no momento."
    priority = "monitorar"

    if host.get("health_status") == "down":
        state = "O host aparece indisponível no contexto atual."
        impact = "O ativo pode estar indisponível ou isolado para a operação."
        priority = "agir agora"
        facts.append("O estado de saúde do host está down.")
        inferences.append("Há indisponibilidade do ativo ou do caminho até ele.")
        limits.append("Sem validação de topologia e de acesso físico, não dá para afirmar se a causa está no host, na borda ou no caminho.")
        runbook_keys.append("host_down")

    if loop_incident or loop_prediction or loop_groups or mac_groups:
        state = "Há risco operacional relevante de camada 2 no host."
        impact = (
            "O segmento L2 afetado pode degradar ou ficar indisponível. "
            "Não há base para afirmar queda da rede inteira sem topologia completa."
        )
        priority = "agir agora"
        runbook_keys.extend(["loop_risk", "broadcast_storm", "mac_flapping"])

        if loop_incident:
            facts.append(
                f"Incidente loop_risk {loop_incident.get('severity') or 'sem severidade'} aberto: {loop_incident.get('title') or 'sem título'}."
            )
        if loop_prediction:
            score_pct = int(round(float(loop_prediction.get("score") or 0) * 100))
            facts.append(
                f"Predição loop_risk recente com score {score_pct}% no período analisado."
            )
        for item in loop_groups:
            facts.append(format_host_signal_group_for_prompt(item))
        for item in mac_groups:
            secondary.append(format_host_signal_group_for_prompt(item))

        stp_disabled = any(
            "stp desabilitado" in str(message or "").lower()
            for item in loop_groups
            for message in (item.get("messages") or [])
        )
        if stp_disabled:
            secondary.append("Os syslogs recentes citam STP desabilitado no segmento suspeito.")

        if loop_groups and mac_groups:
            inferences.append(
                "A combinação de storm e MAC flapping sugere loop L2, redundância indevida ou instabilidade de camada 2 no par afetado."
            )
        elif loop_groups:
            inferences.append(
                "Os sinais de storm ou de proteção L2 sugerem loop L2, flooding anormal ou redundância indevida no segmento afetado."
            )
        elif mac_groups:
            inferences.append(
                "O MAC flapping recorrente sugere instabilidade de camada 2, possível loop L2 ou redundância indevida no caminho afetado."
            )
        elif loop_signal_contexts:
            inferences.append(
                "O incidente aberto indica risco de loop L2 a partir de uma correlação anterior de sinais de camada 2."
            )
        limits.append(
            "Sem topologia completa e sem validação direta do switch, não dá para afirmar qual enlace físico fecha o loop nem o alcance exato do impacto."
        )

    if flap_groups:
        runbook_keys.append("interface_flap")
        for item in flap_groups:
            secondary.append(format_host_signal_group_for_prompt(item))
        inferences.append(
            "O flap recorrente pode ser um problema distinto de porta, cabo, óptico ou configuração, separado do possível loop quando ocorre em outra interface."
        )

    if trap_groups:
        for item in trap_groups:
            supporting.append(format_host_signal_group_for_prompt(item))

    for prediction in predictions:
        metric = str(prediction.get("metric") or "").strip().lower()
        if metric == "loop_risk":
            continue
        if not ai_prediction_is_relevant(prediction):
            continue
        severity = str(prediction.get("severity") or "")
        if_name = prediction.get("if_name")
        location = f" em {if_name}" if if_name else ""
        score_pct = int(round(ai_prediction_score(prediction) * 100))
        line = f"Anomalia SNMP {prediction.get('metric')}{location} com severidade {severity or 'sem severidade'} e score {score_pct}%."
        if loop_incident or loop_groups or mac_groups:
            supporting.append(line)
        else:
            secondary.append(line)

    for item in historical_loop_groups:
        supporting.append(f"Historico recente, sem evidencia atual na janela curta: {format_host_signal_group_for_prompt(item)}")
    for item in historical_mac_groups:
        supporting.append(f"Historico recente, sem evidencia atual na janela curta: {format_host_signal_group_for_prompt(item)}")
    for item in historical_flap_groups:
        supporting.append(f"Historico recente, sem evidencia atual na janela curta: {format_host_signal_group_for_prompt(item)}")
    if recent_incidents and not active_incidents:
        last_incident = recent_incidents[0]
        status = normalize_status_value(last_incident.get("status")) or "desconhecido"
        if status in {"resolved", "closed"}:
            supporting.append(
                f"Ultimo incidente relevante esta {status}: {last_incident.get('incident_type') or 'operacional'}."
            )

    for metric in latest_metrics:
        metric_name = str(metric.get("metric") or "").lower()
        value = metric_value_to_float(metric)
        if value is None:
            continue
        if "icmp" in metric_name and "loss" in metric_name and value > 0:
            secondary.append(f"Perda ICMP recente observada em {value:g}% na janela atual.")
            runbook_keys.append("icmp_loss_latency")
        if "icmp" in metric_name and any(token in metric_name for token in ("rtt", "latency")) and value >= 100:
            secondary.append(f"Latência ICMP recente acima do esperado ({value:g}).")
            runbook_keys.append("icmp_loss_latency")
        if "snmp" in metric_name and any(token in metric_name for token in ("availability", "reachable", "up")) and value <= 0:
            secondary.append("Há indicativo recente de indisponibilidade de coleta SNMP.")
            runbook_keys.append("snmp_indisponivel")

    if any(severity_rank(item.get("severity")) >= severity_rank("high") for item in recent_syslog):
        supporting.append("Há syslog recente de alta severidade associado ao host.")
        runbook_keys.append("syslog_critical")

    if not facts and not secondary and supporting:
        state = "Sem incidente aberto ou sinal atual relevante; ha evidencias historicas no periodo analisado."
        impact = "Sem evidencia atual suficiente para afirmar impacto operacional ativo."
        priority = "monitorar"

    latest_context_ts_candidates = [
        parse_ai_timestamp(host.get("last_activity_at")),
        parse_ai_timestamp(host.get("last_collection_at")),
    ]
    latest_context_ts_candidates.extend(parse_ai_timestamp(item.get("ts")) for item in recent_syslog)
    latest_context_ts = max((item for item in latest_context_ts_candidates if item is not None), default=None)
    incident_last_seen = parse_ai_timestamp(loop_incident.get("last_seen_at")) if loop_incident else None
    if incident_last_seen and latest_context_ts and (latest_context_ts - incident_last_seen).total_seconds() > 300:
        limits.append(
            "O incidente loop_risk aberto reflete uma correlação anterior; o recorte mais recente do host não repete todos os mesmos sinais na mesma intensidade."
        )

    if not facts and not secondary and not supporting:
        facts.append("Nenhum incidente relevante ou correlação forte foi identificado no período analisado.")
        limits.append("Sem sinais operacionais relevantes, a recomendação correta é acompanhamento e nova conferência se surgirem mudanças.")

    return {
        "state": state,
        "impact": impact,
        "priority": priority,
        "facts": dedupe_text_items(facts)[:6],
        "secondary_findings": dedupe_text_items(secondary)[:8],
        "supporting_signals": dedupe_text_items(supporting)[:6],
        "inferences": dedupe_text_items(inferences)[:4],
        "limits": dedupe_text_items(limits)[:4],
        "runbooks": build_runbook_entries(runbook_keys)[:4],
    }


def build_incident_operational_assessment(context: dict[str, Any]) -> dict[str, Any]:
    incident = context.get("incident") or {}
    host = context.get("host") or {}
    signal_contexts = list(incident.get("signal_contexts") or [])
    facts: list[str] = []
    supporting: list[str] = []
    inferences: list[str] = []
    limits: list[str] = []
    runbook_keys: list[str] = []

    severity = str(incident.get("severity") or "")
    incident_type = str(incident.get("incident_type") or "")
    state = f"Há um incidente {incident_type or 'operacional'} ativo para o host."
    impact = "O impacto exato depende do contexto da rede e do alcance do segmento afetado."
    priority = "agir agora" if severity_rank(severity) >= severity_rank("high") else "acompanhar"

    if incident.get("opening_reason"):
        facts.append(str(incident.get("opening_reason")))

    for item in signal_contexts:
        label = str(item.get("label") or item.get("signal") or "Sinal")
        focus = str(item.get("focus") or "host")
        count = int(item.get("count") or 0)
        facts.append(f"{label} em {focus} ({count} ocorrência(s)).")
        signal = str(item.get("signal") or "").strip().upper()
        if signal == "BROADCAST_STORM":
            runbook_keys.extend(["loop_risk", "broadcast_storm"])
        elif signal == "MAC_FLAPPING":
            runbook_keys.append("mac_flapping")
        elif signal == "INTERFACE_FLAP":
            runbook_keys.append("interface_flap")

    for hint in incident.get("snmp_hints") or []:
        metric = hint.get("metric")
        key = hint.get("key")
        supporting.append(f"Degradação SNMP correlata em {key or metric or 'sinal SNMP'}")

    if incident_type == "loop_risk":
        state = "Há um incidente de risco de loop L2 ativo para o host."
        impact = (
            "O segmento L2 envolvido pode degradar ou ficar indisponível. "
            "Sem topologia completa, não há base para afirmar a parada da rede inteira."
        )
        inferences.append(
            "A correlação entre storm, MAC flapping e sinais adicionais é compatível com loop L2 ou redundância indevida."
        )
        limits.append(
            "O NetGuard não consegue afirmar sozinho qual enlace físico fecha o loop nem o alcance total do impacto sem topologia completa."
        )

    if host.get("health_status") == "down":
        supporting.append("O host também aparece com saúde down no contexto operacional.")
        runbook_keys.append("host_down")

    if not limits:
        limits.append("Sem validação de topologia e sem intervenção no equipamento, a análise continua limitada às evidências do NetGuard.")

    return {
        "state": state,
        "impact": impact,
        "priority": priority,
        "facts": dedupe_text_items(facts)[:6],
        "secondary_findings": [],
        "supporting_signals": dedupe_text_items(supporting)[:6],
        "inferences": dedupe_text_items(inferences)[:4],
        "limits": dedupe_text_items(limits)[:4],
        "runbooks": build_runbook_entries(runbook_keys)[:4],
    }


def render_operational_assessment_digest(assessment: dict[str, Any]) -> str:
    if not assessment:
        return ""

    lines = [
        "Politica operacional orientadora:",
        f"- Estado atual: {assessment.get('state') or '-'}",
        f"- Impacto provável: {assessment.get('impact') or '-'}",
        f"- Prioridade: {assessment.get('priority') or '-'}",
    ]

    facts = assessment.get("facts") or []
    if facts:
        lines.append("Fatos observados pelo NetGuard:")
        lines.extend(f"- {item}" for item in facts[:6])

    secondary = assessment.get("secondary_findings") or []
    if secondary:
        lines.append("Demais achados relevantes:")
        lines.extend(f"- {item}" for item in secondary[:6])

    supporting = assessment.get("supporting_signals") or []
    if supporting:
        lines.append("Sinais de apoio:")
        lines.extend(f"- {item}" for item in supporting[:6])

    inferences = assessment.get("inferences") or []
    if inferences:
        lines.append("Inferencias operacionais:")
        lines.extend(f"- {item}" for item in inferences[:4])

    limits = assessment.get("limits") or []
    if limits:
        lines.append("Limites do que nao da para afirmar:")
        lines.extend(f"- {item}" for item in limits[:4])

    runbooks = assessment.get("runbooks") or []
    if runbooks:
        lines.append("Runbooks minimos aplicaveis:")
        for item in runbooks[:4]:
            actions = "; ".join(str(action) for action in list(item.get("actions") or [])[:6])
            lines.append(f"- {item.get('title')}: {actions}")

    return "\n".join(lines)


def render_host_context_digest(context: dict[str, Any]) -> str:
    host = context.get("host") or {}
    summary = context.get("findings_summary") or build_host_findings_summary(context)
    assessment = context.get("operational_assessment") or build_host_operational_assessment(context)
    latest_metrics = list(context.get("latest_metrics") or [])
    recent_notifications = list(context.get("recent_notifications") or [])
    lines = [
        "Host em foco:",
        f"- Nome: {host.get('name') or '-'}",
        f"- IP: {host.get('ip') or '-'}",
        f"- Grupo: {host.get('group_name') or '-'}",
        f"- Template: {host.get('template_name') or '-'}",
        f"- Saúde: {host.get('health_status') or '-'}",
        f"- Postura operacional: {host.get('operational_posture') or '-'}",
        f"- Incidentes abertos: {host.get('open_incidents') or 0}",
    ]
    if host.get("last_collection_at"):
        lines.append(f"- Última coleta: {host.get('last_collection_at')}")
    if host.get("last_activity_at"):
        lines.append(f"- Última atividade: {host.get('last_activity_at')}")
    if latest_metrics:
        lines.append("Métricas recentes:")
        for item in latest_metrics[:4]:
            metric_name = format_metric_name(item.get("metric"))
            value = item.get("value")
            unit = item.get("unit")
            if value is None:
                continue
            suffix = f" {unit}" if unit else ""
            lines.append(f"- {metric_name}: {value}{suffix}")
    if recent_notifications:
        lines.append("Notificações recentes:")
        for item in recent_notifications[:4]:
            lines.append(
                f"- {item.get('channel') or '-'} | {item.get('provider') or '-'} | {item.get('delivery_status') or '-'} | {item.get('sent_at') or '-'}"
            )
    loop_ts = parse_ai_timestamp(host.get("loop_risk_ts"))
    loop_score = host.get("loop_risk_score")
    if (
        loop_score is not None
        and loop_ts is not None
        and (datetime.now(timezone.utc) - loop_ts).total_seconds() <= AI_RECENT_SIGNAL_WINDOW_SECONDS
    ):
        lines.append(f"- Loop risk atual: {loop_score}")
    elif loop_score is not None:
        lines.append(
            f"- Loop risk atual: sem evidencia atual; ultimo score historico {loop_score} em {host.get('loop_risk_ts') or '-'}"
        )
    else:
        lines.append("- Loop risk atual: -")

    if summary.get("primary_issue"):
        lines.append("Problema principal:")
        lines.append(f"- {summary['primary_issue']}")

    problems = summary.get("problems") or []
    if problems:
        lines.append("Demais problemas identificados no período:")
        lines.extend(f"- {item}" for item in problems)

    if not problems and int(host.get("open_incidents") or 0) == 0:
        lines.append("Problemas atuais:")
        lines.append("- Nenhum incidente aberto ou sinal atual relevante foi identificado no recorte atual.")

    supporting = summary.get("supporting_signals") or []
    if supporting:
        lines.append("Sinais de apoio:")
        lines.extend(f"- {item}" for item in supporting)

    historical = summary.get("historical_signals") or []
    if historical:
        lines.append("Historico recente sem evidencia atual (nao classificar como problema ativo):")
        lines.extend(f"- {item}" for item in historical)

    return "\n".join(lines)


def render_incident_context_digest(context: dict[str, Any]) -> str:
    incident = context.get("incident") or {}
    host = context.get("host") or {}
    assessment = context.get("operational_assessment") or build_incident_operational_assessment(context)
    recent_notifications = list(context.get("recent_notifications") or [])
    recent_syslog = list(context.get("recent_syslog") or [])
    lines = [
        "Incidente em foco:",
        f"- Título: {incident.get('title') or '-'}",
        f"- Tipo: {incident.get('incident_type') or '-'}",
        f"- Severidade: {incident.get('severity') or '-'}",
        f"- Status: {incident.get('status') or '-'}",
        f"- Host: {host.get('name') or '-'} ({host.get('ip') or '-'})",
    ]
    if incident.get("opened_at"):
        lines.append(f"- Abertura: {incident.get('opened_at')}")
    if incident.get("last_seen_at"):
        lines.append(f"- Última ocorrência: {incident.get('last_seen_at')}")
    if incident.get("opening_reason"):
        lines.append(f"- Motivo de abertura: {incident.get('opening_reason')}")
    if incident.get("affected_contexts"):
        lines.append(f"- Contextos afetados: {' | '.join(str(item) for item in incident.get('affected_contexts') or [])}")
    if recent_syslog:
        lines.append("Syslog recente:")
        for item in recent_syslog[:4]:
            text_item = str(item.get("message") or item.get("summary") or "").strip()
            if text_item:
                lines.append(f"- {text_item}")
    signal_contexts = incident.get("signal_contexts") or []
    if signal_contexts:
        lines.append("Sinais correlacionados:")
        for item in signal_contexts[:6]:
            label = item.get("label") or item.get("signal") or "Sinal"
            focus = item.get("focus") or "host"
            count = int(item.get("count") or 0)
            lines.append(f"- {label} em {focus} ({count} ocorrência(s))")
    if recent_notifications:
        lines.append("Notificações recentes:")
        for item in recent_notifications[:4]:
            lines.append(
                f"- {item.get('channel') or '-'} | {item.get('provider') or '-'} | {item.get('delivery_status') or '-'} | {item.get('sent_at') or '-'}"
            )
    recommendation = incident.get("recommendation")
    if recommendation:
        lines.append(f"- Recomendação atual: {recommendation}")
    assessment_block = render_operational_assessment_digest(assessment)
    if assessment_block:
        lines.append(assessment_block)
    return "\n".join(lines)


def render_environment_context_digest(context: dict[str, Any]) -> str:
    environment = context.get("environment") or {}
    priority_hosts = list(context.get("priority_hosts") or [])
    active_incidents = list(context.get("active_incidents") or [])
    lines = [
        "Contexto do ambiente:",
        f"- Hosts totais: {environment.get('total_hosts') or 0}",
        f"- Hosts ativos: {environment.get('active_hosts') or 0}",
        f"- Incidentes abertos: {environment.get('open_incidents') or 0}",
        f"- Loop risk aberto: {environment.get('open_loop_risk') or 0}",
    ]
    if priority_hosts:
        lines.append("Hosts prioritários:")
        for host in priority_hosts[:4]:
            lines.append(
                f"- {host.get('name') or '-'} ({host.get('ip') or '-'}) | saúde {host.get('health_status') or '-'} | incidentes {host.get('open_incidents') or 0} | loop_risk {host.get('loop_risk_score') if host.get('loop_risk_score') is not None else '-'}"
            )
    if active_incidents:
        lines.append("Incidentes abertos mais relevantes no ambiente:")
        for incident in active_incidents[:4]:
            lines.append(
                f"- {incident.get('title') or '-'} | tipo {incident.get('incident_type') or '-'} | severidade {incident.get('severity') or '-'} | host {incident.get('hostname') or incident.get('src_ip') or '-'}"
            )
    return "\n".join(lines)


def render_environment_secondary_digest(
    context: dict[str, Any],
    *,
    focus_host_id: Optional[int] = None,
) -> str:
    environment = context.get("environment") or {}
    priority_hosts = list(context.get("priority_hosts") or [])
    secondary_hosts = [
        host
        for host in priority_hosts
        if focus_host_id is None or int(host.get("id") or 0) != int(focus_host_id)
    ]
    healthy_secondary_hosts = [
        host
        for host in secondary_hosts
        if int(host.get("open_incidents") or 0) == 0
        and severity_rank(host.get("max_incident_severity")) <= 0
        and float(host.get("loop_risk_score") or 0) < 0.2
    ]

    lines = ["Contexto secundario do ambiente:"]
    if healthy_secondary_hosts:
        names = ", ".join(str(host.get("name") or "-") for host in healthy_secondary_hosts[:3])
        lines.append(f"- Outros hosts saudaveis ou sem relacao direta com o problema principal: {names}")
    elif secondary_hosts:
        names = ", ".join(str(host.get("name") or "-") for host in secondary_hosts[:3])
        lines.append(f"- Outros hosts monitorados no ambiente: {names}")
    return "\n".join(lines)


def render_chat_focus_digest(context: dict[str, Any]) -> str:
    active_operational_brief = context.get("active_operational_brief") or {}
    focus_resolution = context.get("focus_resolution") or {}
    focus_host = context.get("focus_host") or {}
    focus_incident = context.get("focus_incident") or {}
    active_incidents = list(context.get("active_incidents") or [])
    recent_operational_signals = list(context.get("recent_operational_signals") or [])
    incident_supporting_evidence = list(context.get("incident_supporting_evidence") or [])
    stale_or_historical_evidence = list(context.get("stale_or_historical_evidence") or [])
    low_relevance_signals = list(context.get("low_relevance_signals") or [])
    assessment = context.get("operational_assessment") or {}

    lines = ["Foco operacional resolvido para esta conversa:"]
    if focus_resolution.get("mode"):
        lines.append(f"- Modo de foco: {focus_resolution.get('mode')}")
    if focus_resolution.get("reason"):
        lines.append(f"- Motivo: {focus_resolution.get('reason')}")
    if focus_host:
        lines.append(
            f"- Host principal: {focus_host.get('name') or '-'} ({focus_host.get('ip') or '-'}) | postura {focus_host.get('operational_posture') or '-'} | incidentes {focus_host.get('open_incidents') or 0}"
        )
    if focus_incident:
        lines.append(
            f"- Incidente principal: {focus_incident.get('title') or '-'} | tipo {focus_incident.get('incident_type') or '-'} | severidade {focus_incident.get('severity') or '-'} | status {focus_incident.get('status') or '-'}"
        )
    assessment_block = render_operational_assessment_digest(assessment)
    if assessment_block:
        lines.append(assessment_block)
    if active_incidents and not active_operational_brief:
        lines.append("Incidentes ativos considerados para priorização:")
        for item in active_incidents[:4]:
            lines.append(
                f"- {item.get('title') or '-'} | severidade {item.get('severity') or '-'} | último sinal {item.get('last_seen_at') or item.get('opened_at') or '-'}"
            )
    if recent_operational_signals and not active_operational_brief:
        lines.append("Sinais operacionais recentes da janela atual:")
        for item in recent_operational_signals[:8]:
            lines.append(f"- {item.get('summary') or '-'} | último sinal {item.get('last_seen') or '-'}")
    if incident_supporting_evidence and not active_operational_brief:
        lines.append("Evidências que sustentam o incidente aberto:")
        for item in incident_supporting_evidence[:6]:
            lines.append(f"- {item.get('summary') or '-'}")
    if stale_or_historical_evidence and not active_operational_brief:
        lines.append("Evidências históricas ou fora da janela recente:")
        for item in stale_or_historical_evidence[:6]:
            lines.append(f"- {item.get('summary') or '-'}")
    if low_relevance_signals and not active_operational_brief:
        lines.append("Sinais de baixa relevância operacional:")
        for item in low_relevance_signals[:4]:
            lines.append(f"- {item.get('summary') or '-'}")

    return "\n".join(lines)


def render_product_context_digest(context: dict[str, Any]) -> str:
    enabled_templates = list(context.get("enabled_templates") or [])
    enabled_names = ", ".join(template.get("name") or "-" for template in enabled_templates[:5]) or "-"
    planned_templates = ", ".join(str(item) for item in list(context.get("planned_templates") or [])[:5]) or "-"
    current_capabilities = list(context.get("current_capabilities") or [])
    article_context = context.get("article_context") if isinstance(context.get("article_context"), dict) else {}
    lines = [
        "Contexto do produto NetGuard:",
        f"- Resumo: {context.get('product_summary') or '-'}",
        f"- Posicionamento: {context.get('product_positioning') or '-'}",
        f"- Escopo atual: {context.get('current_scope_statement') or '-'}",
        f"- Templates ativos: {enabled_names}",
        f"- Templates planejados: {planned_templates}",
    ]
    if article_context:
        lines.append(f"- Tema do artigo/TCC: {article_context.get('theme') or '-'}")
        lines.append(f"- Regra de comparacao: {article_context.get('comparison_guardrail') or '-'}")
        metrics = list(article_context.get("evaluation_metrics") or [])
        if metrics:
            lines.append("Metricas para artigo/TCC:")
            lines.extend(f"- {item}" for item in metrics[:6])
    if current_capabilities:
        lines.append("Capacidades atuais:")
        lines.extend(f"- {item}" for item in current_capabilities[:6])
    return "\n".join(lines)


def build_prompt_context_digest(context: dict[str, Any], *, prompt_mode: str) -> str:
    scope = str(context.get("scope") or "")
    sections: list[str] = []

    if scope == "host":
        sections.append(render_host_context_digest(context))
    elif scope == "incident":
        sections.append(render_incident_context_digest(context))
    elif scope == "technical_summary":
        environment = context.get("environment") or {}
        sections.append(
            "\n".join(
                [
                    "Resumo técnico do ambiente:",
                    f"- Hosts totais: {environment.get('total_hosts') or 0}",
                    f"- Hosts ativos: {environment.get('active_hosts') or 0}",
                    f"- Incidentes abertos: {environment.get('open_incidents') or 0}",
                    f"- Loop risk aberto: {environment.get('open_loop_risk') or 0}",
                ]
            )
        )
        if context.get("focus_host"):
            sections.append(render_host_context_digest(context["focus_host"]))
        if context.get("focus_incident"):
            sections.append(render_incident_context_digest(context["focus_incident"]))
    elif scope == "chat":
        question_kind = str(context.get("question_kind") or "operational")
        if question_kind == "operational" and context.get("active_operational_brief"):
            sections.append(render_active_operational_brief_digest(context.get("active_operational_brief") or {}))
        sections.append(render_chat_focus_digest(context))
        if context.get("host_context"):
            sections.append(render_host_context_digest(context["host_context"]))
        if context.get("incident_context"):
            sections.append(render_incident_context_digest(context["incident_context"]))
        if context.get("environment_context"):
            if question_kind == "operational" and context.get("focus_host"):
                sections.append(
                    render_environment_secondary_digest(
                        context["environment_context"],
                        focus_host_id=(context.get("focus_host") or {}).get("id"),
                    )
                )
            else:
                sections.append(render_environment_context_digest(context["environment_context"]))
        if question_kind in {"product", "comparison", "presentation", "conceptual", "article", "network"} and context.get("product_context"):
            sections.append(render_product_context_digest(context["product_context"]))
        if context.get("response_contract"):
            sections.append(render_response_contract_digest(context.get("response_contract")))
    else:
        sections.append(json.dumps(context, ensure_ascii=False, indent=2))

    return "\n\n".join(section for section in sections if section.strip())


def ai_output_looks_incomplete(text: str, raw: Optional[dict[str, Any]] = None) -> bool:
    content = str(text or "").strip()
    if not content:
        return True

    done_reason = str((raw or {}).get("done_reason") or "").strip().lower()
    if done_reason == "length":
        return True

    normalized_tail = normalize_chat_message(content[-80:])
    if any(normalized_tail.endswith(item) for item in ("a secao", "o json fornecido", "o json", "o contexto", "a resposta")):
        return True

    return content[-1] not in ".!?)]}\"”"


def ai_output_is_meta_descriptive(text: str) -> bool:
    normalized = normalize_chat_message(text[:240])
    unwanted_snippets = (
        "o json fornecido",
        "a secao",
        "a estrutura",
        "o contexto fornecido",
        "o json mostra",
        "a secao hosts",
    )
    return any(snippet in normalized for snippet in unwanted_snippets)


def ai_output_has_weak_ending(text: str) -> bool:
    content = str(text or "").rstrip()
    if not content:
        return True
    return content.endswith((":", ";", "-"))


def generate_ai_text(
    *,
    system: str,
    prompt: str,
    temperature: float,
    num_predict: int,
    allow_retry: bool = True,
) -> OllamaGenerateResult:
    client = OllamaClient()
    result = client.generate(
        system=system,
        prompt=prompt,
        temperature=temperature,
        num_predict=num_predict,
    )

    needs_retry = (
        ai_output_looks_incomplete(result.response, result.raw)
        or ai_output_is_meta_descriptive(result.response)
        or ai_output_has_weak_ending(result.response)
    )
    if not needs_retry or not allow_retry:
        return result

    retry_prompt = (
        f"{prompt}\n\n"
        "Ajuste obrigatório para esta nova tentativa:\n"
        "- responda diretamente à pergunta ou tarefa, sem comentar JSON, estrutura, seções ou contexto bruto;\n"
        "- cubra todos os achados reais relevantes, do principal aos secundários e sinais de apoio;\n"
        "- use severidade apenas para priorizar, nunca para omitir um achado real;\n"
        "- feche a resposta com frases completas.\n"
    )
    return client.generate(
        system=system,
        prompt=retry_prompt,
        temperature=min(temperature, 0.1),
        num_predict=min(max(num_predict + 160, 560), 840),
    )


def compact_incident_for_ai(incident: dict[str, Any]) -> dict[str, Any]:
    details = incident.get("details") or {}
    evidences = details.get("evidences") or details.get("evidence") or []
    signal_contexts = prioritize_incident_signal_contexts(list(details.get("signal_contexts") or []), limit=8)
    return {
        "id": incident.get("id"),
        "title": incident.get("title"),
        "incident_type": incident.get("incident_type"),
        "severity": incident.get("severity"),
        "status": incident.get("status"),
        "asset_id": incident.get("asset_id"),
        "hostname": incident.get("hostname"),
        "src_ip": incident.get("src_ip"),
        "opened_at": incident.get("opened_at"),
        "last_seen_at": incident.get("last_seen_at"),
        "recommendation": details.get("recommendation"),
        "evidences": evidences[:6] if isinstance(evidences, list) else [],
        "signal_counts": details.get("signal_counts") if isinstance(details.get("signal_counts"), dict) else {},
        "snmp_hints": trim_ai_items(details.get("snmp_hints") or [], 4),
        "signal_contexts": trim_ai_items(signal_contexts, 8),
        "affected_contexts": trim_ai_items(details.get("affected_contexts") or [], 6),
        "opening_reason": details.get("opening_reason"),
        "group_name": incident.get("group_path") or incident.get("group_name"),
        "template_name": incident.get("template_name"),
    }


def compact_incident_notification_for_ai(notification: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": notification.get("id"),
        "incident_id": notification.get("incident_id"),
        "channel": notification.get("channel"),
        "provider": notification.get("provider"),
        "delivery_status": notification.get("delivery_status"),
        "error": notification.get("error"),
        "sent_at": notification.get("sent_at"),
    }


def select_incident_notification_records(cur, *, incident_id: int, limit: int = 6) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT id, incident_id, channel, provider, delivery_status, error, sent_at
        FROM incident_notifications
        WHERE incident_id = %s
        ORDER BY sent_at DESC, id DESC
        LIMIT %s
        """,
        (incident_id, limit),
    )
    rows = cur.fetchall()
    return [
        compact_incident_notification_for_ai(
            {
                "id": row[0],
                "incident_id": row[1],
                "channel": row[2],
                "provider": row[3],
                "delivery_status": row[4],
                "error": row[5],
                "sent_at": to_iso(row[6]),
            }
        )
        for row in rows
    ]


def compact_syslog_for_ai(event: dict[str, Any]) -> dict[str, Any]:
    raw_text = str(event.get("message") or event.get("raw") or "")
    interface_pair = extract_interface_pair_from_text(
        event.get("iface"),
        event.get("message"),
        event.get("raw"),
    )
    interfaces = extract_interface_names_from_text(
        event.get("iface"),
        event.get("message"),
        event.get("raw"),
    )
    resolved_iface = normalize_interface_name(event.get("iface"))
    if not resolved_iface and len(interfaces) == 1:
        resolved_iface = interfaces[0]
    signal_type = classify_host_signal(raw_text)
    return {
        "ts": event.get("ts"),
        "severity": event.get("severity"),
        "subsystem": event.get("subsystem"),
        "iface": resolved_iface,
        "interfaces": interfaces,
        "interface_pair": interface_pair.get("label") if interface_pair else None,
        "signal_type": signal_type,
        "signal_label": HOST_AI_SIGNAL_LABELS.get(signal_type, "Syslog"),
        "message": event.get("message"),
    }


def compact_prediction_for_ai(prediction: dict[str, Any]) -> dict[str, Any]:
    details = prediction.get("details") or {}
    signal_counts = details.get("signal_counts") if isinstance(details.get("signal_counts"), dict) else {}
    return {
        "ts": prediction.get("ts"),
        "metric": prediction.get("metric"),
        "score": prediction.get("score"),
        "severity": prediction.get("severity"),
        "key": prediction.get("key"),
        "value": prediction.get("value"),
        "z": prediction.get("z"),
        "if_name": normalize_interface_name(extract_prediction_iface_name(prediction)),
        "signal_counts": signal_counts,
        "snmp_hints": trim_ai_items(details.get("snmp_hints") or [], 4),
        "recommendation": details.get("recommendation"),
    }


def compact_metric_for_ai(metric: dict[str, Any]) -> dict[str, Any]:
    labels = metric.get("labels") or {}
    return {
        "metric": metric.get("metric"),
        "value": metric.get("value"),
        "ts": metric.get("ts"),
        "if_name": labels.get("ifName"),
        "unit": metric.get("unit"),
    }


def infer_operational_posture(host: dict[str, Any]) -> str:
    health = str(host.get("health_status") or "").strip().lower()
    open_incidents = int(host.get("open_incidents") or 0)
    loop_risk_score = float(host.get("loop_risk_score") or 0)
    loop_ts = parse_ai_timestamp(host.get("loop_risk_ts"))
    loop_is_current = (
        loop_ts is not None
        and (datetime.now(timezone.utc) - loop_ts).total_seconds() <= AI_RECENT_SIGNAL_WINDOW_SECONDS
    )

    if health == "down":
        return "critical"
    if open_incidents > 0 or (loop_is_current and loop_risk_score >= 0.5):
        return "attention"
    if health == "healthy" and open_incidents == 0 and (not loop_is_current or loop_risk_score < 0.2):
        return "stable"
    if health == "inactive":
        return "inactive"
    return "observe"


def humanize_health_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    labels = {
        "healthy": "Saudável",
        "up": "Saudável",
        "degraded": "Degradado",
        "attention": "Degradado",
        "observe": "Monitorar",
        "down": "Crítico",
        "critical": "Crítico",
        "inactive": "Inativo",
        "maintenance": "Em manutenção",
        "paused": "Monitoramento pausado",
        "unknown": "Desconhecido",
    }
    return labels.get(normalized, normalized.title() if normalized else "Desconhecido")


def build_host_ai_context(cur, host_id: int, *, hours: int = 24) -> dict[str, Any]:
    to_ts = datetime.now(timezone.utc)
    from_ts = to_ts - timedelta(hours=hours)
    host = get_host_record(cur, host_id)
    attach_host_operational_state(cur, [host], from_ts, to_ts)

    profiles = list_host_profile_records(cur, host_id)
    if bool(host.get("enabled", True)):
        active_incident_records = select_incident_records(
            cur,
            host_record=host,
            status="open",
            limit=4,
            active_hosts_only=True,
        )
    else:
        active_incident_records = []
    recent_window_incidents = select_incident_records(cur, host_record=host, from_ts=from_ts, to_ts=to_ts, limit=6)
    incidents = merge_incident_records(active_incident_records, recent_window_incidents, limit=6)
    syslog_events = select_syslog_records(cur, host_record=host, from_ts=from_ts, to_ts=to_ts, limit=256)
    predictions = select_prediction_records(cur, asset_id=host_id, from_ts=from_ts, to_ts=to_ts, limit=12)
    metrics = select_metric_records(cur, asset_id=host_id, from_ts=from_ts, to_ts=to_ts, limit=24)
    compact_syslog_events = [compact_syslog_for_ai(item) for item in syslog_events]
    compact_predictions = [compact_prediction_for_ai(item) for item in predictions]
    prioritized_syslog_events = prioritize_compact_syslog_for_ai(compact_syslog_events, limit=12)
    signal_groups = build_host_signal_groups(compact_syslog_events, compact_predictions)
    recent_operational_signals = build_recent_operational_signal_entries(signal_groups, limit=10)
    compact_active_incidents = trim_ai_items([compact_incident_for_ai(item) for item in active_incident_records], 4)
    compact_recent_incidents = trim_ai_items([compact_incident_for_ai(item) for item in incidents], 4)
    lead_incident = compact_active_incidents[0] if compact_active_incidents else (compact_recent_incidents[0] if compact_recent_incidents else None)
    incident_ids_for_notifications = dedupe_text_items(
        [str(item.get("id")) for item in [*compact_active_incidents, *compact_recent_incidents] if item.get("id") is not None]
    )
    recent_notifications = []
    if incident_ids_for_notifications:
        try:
            cur.execute(
                """
                SELECT id, incident_id, channel, provider, delivery_status, error, sent_at
                FROM incident_notifications
                WHERE incident_id = ANY(%s)
                ORDER BY sent_at DESC, id DESC
                LIMIT 12
                """,
                ([int(item) for item in incident_ids_for_notifications],),
            )
            recent_notifications = [
                compact_incident_notification_for_ai(
                    {
                        "id": row[0],
                        "incident_id": row[1],
                        "channel": row[2],
                        "provider": row[3],
                        "delivery_status": row[4],
                        "error": row[5],
                        "sent_at": to_iso(row[6]),
                    }
                )
                for row in cur.fetchall()
            ]
        except Exception:
            recent_notifications = []

    latest_metrics: list[dict[str, Any]] = []
    seen_metrics: set[str] = set()
    for metric in metrics:
        metric_name = str(metric.metric or "")
        if metric_name in seen_metrics:
            continue
        seen_metrics.add(metric_name)
        latest_metrics.append(compact_metric_for_ai(metric.model_dump()))
        if len(latest_metrics) >= 5:
            break

    dashboard = build_grafana_dashboard(
        resolve_host_dashboard_key(host),
        owner_type="host",
        owner_id=host_id,
        variables={"asset_id": host_id},
        title=f"Visualização de {host['name']}",
        description=f"Dashboard associado ao template {host.get('template_name') or 'Sem template legado'}.",
        context={
            "host_name": host["name"],
            "template_name": host.get("template_name"),
            "group_name": host.get("group_path") or host.get("group_name"),
        },
        from_ts=from_ts,
        to_ts=to_ts,
    )

    context = {
        "scope": "host",
        "time_window": {
            "from": to_iso(from_ts),
            "to": to_iso(to_ts),
            "hours": hours,
        },
        "host": {
            "id": host["id"],
            "name": host["name"],
            "ip": host["ip"],
            "group_name": host.get("group_path") or host.get("group_name"),
            "template_name": host.get("template_name"),
            "template_slug": host.get("template_slug"),
            "health_status": host.get("health_status"),
            "operational_posture": infer_operational_posture(host),
            "open_incidents": host.get("open_incidents"),
            "max_incident_severity": host.get("max_incident_severity"),
            "last_incident_title": host.get("last_incident_title"),
            "last_incident_at": host.get("last_incident_at"),
            "last_collection_at": host.get("last_collection_at"),
            "last_activity_at": host.get("last_activity_at"),
            "loop_risk_score": host.get("loop_risk_score"),
            "loop_risk_ts": host.get("loop_risk_ts"),
        },
        "profiles": trim_ai_items([
            {
                "display_name": profile.get("display_name"),
                "kind": profile.get("kind"),
                "enabled": profile.get("enabled"),
            }
            for profile in profiles
        ], 6),
        "latest_metrics": latest_metrics,
        "active_incidents": compact_active_incidents,
        "recent_incidents": compact_recent_incidents,
        "recent_syslog": trim_ai_items(prioritized_syslog_events, 12),
        "recent_predictions": trim_ai_items(compact_predictions, 6),
        "recent_notifications": trim_ai_items(recent_notifications, 8),
        "signal_groups": signal_groups,
        "recent_operational_signals": recent_operational_signals,
        "incident_supporting_evidence": build_incident_supporting_evidence_entries(lead_incident, limit=8),
        "stale_or_historical_evidence": [],
        "low_relevance_signals": build_low_relevance_signal_entries(compact_predictions, limit=6),
        "findings_summary": {},
        "operational_assessment": {},
        "dashboard_context": {
            "title": dashboard["title"],
            "dashboard_key": dashboard["dashboard_key"],
            "kind": dashboard["kind"],
            "variables": dashboard["variables"],
        },
    }
    context["stale_or_historical_evidence"] = build_stale_or_historical_evidence_entries(
        lead_incident,
        host=context.get("host"),
        recent_operational_signals=context.get("recent_operational_signals"),
        recent_syslog=context.get("recent_syslog"),
        limit=6,
    )
    context["findings_summary"] = build_host_findings_summary(context)
    context["operational_assessment"] = build_host_operational_assessment(context)
    return context


def build_incident_ai_context(cur, incident_id: int, *, hours: int = 24) -> dict[str, Any]:
    incident = get_incident_record(cur, incident_id)
    host = None

    if incident.get("asset_id") is not None:
        host = get_host_record(cur, int(incident["asset_id"]))
        attach_host_operational_state(cur, [host])
    else:
        host = find_host_by_name_or_ip(cur, incident.get("hostname") or "", incident.get("src_ip") or "")

    to_ts = datetime.now(timezone.utc)
    from_ts = to_ts - timedelta(hours=hours)
    recent_syslog_records: list[dict[str, Any]] = []
    recent_prediction_records: list[dict[str, Any]] = []
    if host:
        recent_syslog_records = select_syslog_records(cur, host_record=host, from_ts=from_ts, to_ts=to_ts, limit=256)
        if host.get("id") is not None:
            recent_prediction_records = select_prediction_records(cur, asset_id=int(host["id"]), from_ts=from_ts, to_ts=to_ts, limit=12)

    compact_syslog_events = [compact_syslog_for_ai(item) for item in recent_syslog_records]
    compact_predictions = [compact_prediction_for_ai(item) for item in recent_prediction_records]
    prioritized_syslog_events = prioritize_compact_syslog_for_ai(compact_syslog_events, limit=12)
    signal_groups = build_host_signal_groups(compact_syslog_events, compact_predictions)
    compact_incident = compact_incident_for_ai(incident)

    loop_risk_related = (
        str(incident.get("incident_type") or "").strip().lower() == "loop_risk"
        or str(incident.get("key") or "").strip().lower() == "loop_risk"
    )

    context = {
        "scope": "incident",
        "time_window": {
            "from": to_iso(from_ts),
            "to": to_iso(to_ts),
            "hours": hours,
        },
        "incident": compact_incident,
        "host": {
            "id": host.get("id") if host else None,
            "name": host.get("name") if host else incident.get("hostname"),
            "ip": host.get("ip") if host else incident.get("src_ip"),
            "group_name": incident.get("group_path") or incident.get("group_name"),
            "template_name": incident.get("template_name"),
            "health_status": host.get("health_status") if host else None,
            "operational_posture": infer_operational_posture(host) if host else None,
            "open_incidents": host.get("open_incidents") if host else None,
            "loop_risk_score": host.get("loop_risk_score") if host else None,
        },
        "loop_risk_related": loop_risk_related,
        "recent_syslog": trim_ai_items(prioritized_syslog_events, 12),
        "recent_predictions": trim_ai_items(compact_predictions, 6),
        "recent_notifications": trim_ai_items(select_incident_notification_records(cur, incident_id=incident_id, limit=6), 6),
        "signal_groups": signal_groups,
        "recent_operational_signals": build_recent_operational_signal_entries(signal_groups, limit=10),
        "incident_supporting_evidence": build_incident_supporting_evidence_entries(compact_incident, limit=8),
        "stale_or_historical_evidence": [],
        "low_relevance_signals": build_low_relevance_signal_entries(compact_predictions, limit=6),
    }
    context["stale_or_historical_evidence"] = build_stale_or_historical_evidence_entries(
        compact_incident,
        host=context.get("host"),
        recent_operational_signals=context.get("recent_operational_signals"),
        recent_syslog=context.get("recent_syslog"),
        limit=6,
    )
    context["operational_assessment"] = build_incident_operational_assessment(context)
    return context


def build_technical_summary_context(
    cur,
    *,
    requested_host_id: Optional[int] = None,
    incident_id: Optional[int] = None,
) -> tuple[int, dict[str, Any]]:
    selected_host_id = requested_host_id

    if selected_host_id is None:
        if incident_id is not None:
            cur.execute("SELECT asset_id FROM incidents WHERE id = %s AND asset_id IS NOT NULL", (incident_id,))
            incident_host = cur.fetchone()
            if incident_host and incident_host[0] is not None:
                selected_host_id = int(incident_host[0])

    if selected_host_id is None:
        cur.execute(
            f"""
            SELECT asset_id
            FROM incidents
            WHERE LOWER(status) = 'open'
              AND asset_id IS NOT NULL
            ORDER BY {severity_rank_sql('severity')} DESC,
                     COALESCE(last_seen_at, opened_at) DESC,
                     id DESC
            LIMIT 1
            """
        )
        active_focus = cur.fetchone()
        if active_focus and active_focus[0] is not None:
            selected_host_id = int(active_focus[0])

    if selected_host_id is None:
        demo_host = find_host_by_name_or_ip(cur, DEMO_HOST_NAME, DEMO_HOST_IP)
        selected_host_id = int(demo_host["id"]) if demo_host and demo_host.get("id") is not None else 0

    to_ts = datetime.now(timezone.utc)
    from_ts = to_ts - timedelta(hours=72)

    cur.execute(
        f"""
        SELECT
            COUNT(*) AS total_hosts,
            COUNT(*) FILTER (WHERE enabled) AS active_hosts,
            COUNT(*) FILTER (WHERE NOT enabled) AS inactive_hosts
        FROM {ASSETS_TABLE}
        """
    )
    host_counts = cur.fetchone()

    cur.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE LOWER(status) = 'open') AS open_incidents,
            COUNT(*) FILTER (WHERE LOWER(status) = 'open' AND LOWER(incident_type) = 'loop_risk') AS open_loop_risk
        FROM incidents
        """
    )
    incident_counts = cur.fetchone()

    cur.execute(
        """
        SELECT COUNT(*)
        FROM syslog_events
        WHERE ts >= %s AND ts <= %s
        """,
        (from_ts, to_ts),
    )
    recent_syslog_total = int(cur.fetchone()[0] or 0)

    cur.execute(
        """
        SELECT COUNT(*)
        FROM anomaly_scores
        WHERE ts >= %s AND ts <= %s
        """,
        (from_ts, to_ts),
    )
    recent_prediction_total = int(cur.fetchone()[0] or 0)

    selected_host_context = build_host_ai_context(cur, selected_host_id, hours=72) if selected_host_id else None
    incident_context = build_incident_ai_context(cur, incident_id, hours=72) if incident_id is not None else None

    return selected_host_id or 0, {
        "scope": "technical_summary",
        "time_window": {
            "from": to_iso(from_ts),
            "to": to_iso(to_ts),
            "hours": 72,
        },
        "environment": {
            "total_hosts": int(host_counts[0] or 0),
            "active_hosts": int(host_counts[1] or 0),
            "inactive_hosts": int(host_counts[2] or 0),
            "open_incidents": int(incident_counts[0] or 0),
            "open_loop_risk": int(incident_counts[1] or 0),
            "recent_syslog_total": recent_syslog_total,
            "recent_prediction_total": recent_prediction_total,
        },
        "focus_host": selected_host_context,
        "focus_incident": incident_context,
    }


def compact_host_snapshot_for_ai(host: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": host.get("id"),
        "name": host.get("name"),
        "ip": host.get("ip"),
        "group_name": host.get("group_path") or host.get("group_name"),
        "template_name": host.get("template_name"),
        "health_status": host.get("health_status"),
        "operational_posture": infer_operational_posture(host),
        "open_incidents": host.get("open_incidents"),
        "max_incident_severity": host.get("max_incident_severity"),
        "last_incident_title": host.get("last_incident_title"),
        "last_activity_at": host.get("last_activity_at"),
        "last_collection_at": host.get("last_collection_at"),
        "loop_risk_score": host.get("loop_risk_score"),
    }


def ai_timestamp_epoch(value: Any) -> float:
    parsed = parse_ai_timestamp(value)
    return parsed.timestamp() if parsed else 0.0


def incident_operational_priority(item: dict[str, Any]) -> tuple[int, int, float, int]:
    return (
        1 if str(item.get("status") or "").strip().lower() == "open" else 0,
        severity_rank(item.get("severity")),
        ai_timestamp_epoch(item.get("last_seen_at") or item.get("opened_at")),
        int(item.get("id") or 0),
    )


def host_operational_priority(item: dict[str, Any]) -> tuple[int, int, float, int, float, int]:
    if not bool(item.get("enabled", True)):
        return (
            0,
            0,
            0.0,
            0,
            max(
                ai_timestamp_epoch(item.get("last_activity_at")),
                ai_timestamp_epoch(item.get("last_collection_at")),
            ),
            int(item.get("id") or 0),
        )
    posture = str(item.get("operational_posture") or "").strip().lower()
    posture_rank = {
        "critical": 4,
        "attention": 3,
        "observe": 2,
        "stable": 1,
        "inactive": 0,
    }.get(posture, 0)
    return (
        1 if int(item.get("open_incidents") or 0) > 0 else 0,
        severity_rank(item.get("max_incident_severity")),
        float(item.get("loop_risk_score") or 0),
        posture_rank,
        max(
            ai_timestamp_epoch(item.get("last_incident_at")),
            ai_timestamp_epoch(item.get("last_activity_at")),
            ai_timestamp_epoch(item.get("last_collection_at")),
            ai_timestamp_epoch(item.get("loop_risk_ts")),
        ),
        int(item.get("id") or 0),
    )


def merge_incident_records(*incident_groups: list[dict[str, Any]], limit: int = 6) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for group in incident_groups:
        for item in group:
            incident_id = item.get("id")
            dedupe_key = incident_id if incident_id is not None else (
                item.get("incident_type"),
                item.get("hostname"),
                item.get("src_ip"),
                item.get("opened_at"),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            merged.append(item)
    merged.sort(key=incident_operational_priority, reverse=True)
    return merged[:limit]


def build_recent_operational_signal_entries(
    signal_groups: dict[str, Any],
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for signal_type in HOST_AI_SIGNAL_ORDER:
        for item in list(signal_groups.get(signal_type) or [])[:4]:
            entries.append(
                {
                    "signal_type": signal_type,
                    "signal_label": item.get("signal_label") or HOST_AI_SIGNAL_LABELS.get(signal_type, "Syslog"),
                    "focus": item.get("focus") or "host",
                    "interfaces": trim_ai_items(list(item.get("interfaces") or []), 4),
                    "interface_pair": item.get("interface_pair"),
                    "count": int(item.get("count") or 0),
                    "first_seen": item.get("first_seen"),
                    "last_seen": item.get("last_seen"),
                    "summary": item.get("summary") or format_host_signal_group_for_prompt(item),
                    "messages": trim_ai_items(list(item.get("messages") or []), 2),
                }
            )
            if len(entries) >= limit:
                return entries
    return entries


def build_low_relevance_signal_entries(
    predictions: list[dict[str, Any]],
    *,
    limit: int = 6,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for item in predictions:
        metric = str(item.get("metric") or "").strip().lower()
        if metric == "loop_risk":
            continue
        if not ai_prediction_is_relevant(item, low_signal=True):
            continue
        severity = str(item.get("severity") or "").strip().lower()
        score = ai_prediction_score(item)
        if severity_rank(severity) > severity_rank("info") or score > 0.2:
            continue
        if_name = item.get("if_name")
        location = f" em {if_name}" if if_name else ""
        score_pct = int(round(score * 100))
        entries.append(
            {
                "metric": item.get("metric"),
                "severity": severity or "info",
                "score": score,
                "if_name": if_name,
                "ts": item.get("ts"),
                "summary": f"Sinal SNMP de baixa relevancia {item.get('metric')}{location} com score {score_pct}%.",
            }
        )
    entries.sort(key=lambda item: (float(item.get("score") or 0), ai_timestamp_epoch(item.get("ts"))), reverse=True)
    return entries[:limit]


def build_incident_supporting_evidence_entries(
    incident: Optional[dict[str, Any]],
    *,
    limit: int = 8,
) -> list[dict[str, Any]]:
    if not incident:
        return []

    entries: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, ...]] = set()

    def append_entry(entry: dict[str, Any]) -> None:
        summary = str(entry.get("summary") or "").strip()
        if not summary:
            return
        key = (
            entry.get("kind"),
            entry.get("signal"),
            entry.get("focus"),
            summary,
        )
        if key in seen_keys:
            return
        seen_keys.add(key)
        entries.append(entry)

    signal_counts = incident.get("signal_counts") if isinstance(incident.get("signal_counts"), dict) else {}
    prioritized_counts: list[tuple[str, int]] = []
    for raw_signal, raw_count in signal_counts.items():
        signal = normalize_incident_signal_name(raw_signal)
        count = int(raw_count or 0)
        if not signal or count <= 0:
            continue
        prioritized_counts.append((signal, count))
    prioritized_counts.sort(
        key=lambda item: (
            incident_signal_priority(item[0]),
            -int(item[1] or 0),
            item[0],
        )
    )
    for signal, count in prioritized_counts[:4]:
        category = incident_signal_category(signal)
        label = incident_signal_label(signal)
        if category in {"loop_storm", "mac_flap"}:
            summary = f"{label} fez parte da evidência que sustentou a abertura do incidente ({count} ocorrência(s))."
        elif category == "interface_flap":
            summary = f"{label} sustentou a abertura do incidente ({count} ocorrência(s))."
        elif category == "link_trap":
            summary = f"{label} apareceu na evidência que sustentou a abertura do incidente ({count} ocorrência(s))."
        else:
            summary = f"{label} apareceu na evidência de abertura do incidente ({count} ocorrência(s))."
        append_entry(
            {
                "kind": "signal_count",
                "signal": signal,
                "summary": summary,
                "opened_at": incident.get("opened_at"),
                "last_seen_at": incident.get("last_seen_at"),
            }
        )

    context_limits = {
        "loop_storm": 2,
        "mac_flap": 2,
        "interface_flap": 2,
        "link_trap": 1,
        "other": 1,
    }
    used_contexts: dict[str, int] = {}
    for item in prioritize_incident_signal_contexts(list(incident.get("signal_contexts") or []), limit=12):
        signal = item.get("signal")
        category = incident_signal_category(signal)
        if used_contexts.get(category, 0) >= context_limits.get(category, 1):
            continue
        label = incident_signal_label(signal, str(item.get("label") or item.get("signal") or "Sinal"))
        focus = str(item.get("focus") or "host")
        count = int(item.get("count") or 0)
        append_entry(
            {
                "kind": "signal_context",
                "signal": signal,
                "focus": focus,
                "summary": f"{label} em {focus} ({count} ocorrência(s)).",
                "first_seen_at": item.get("first_seen_at"),
                "last_seen_at": item.get("last_seen_at"),
            }
        )
        used_contexts[category] = used_contexts.get(category, 0) + 1

    evidence_items: list[dict[str, Any]] = []
    for raw_item in list(incident.get("evidences") or []):
        parsed = parse_incident_evidence_token(raw_item)
        if parsed:
            evidence_items.append(parsed)
    evidence_items.sort(
        key=lambda item: (
            incident_signal_priority(item.get("signal")),
            str(item.get("focus") or ""),
        )
    )
    for item in evidence_items[:4]:
        signal = item.get("signal")
        focus = str(item.get("focus") or "host")
        label = incident_signal_label(signal)
        target = f" em {focus}" if focus not in {"", "host", "unknown"} else ""
        append_entry(
            {
                "kind": "evidence_item",
                "signal": signal,
                "focus": focus,
                "summary": f"{label} registrado{target}.",
                "opened_at": incident.get("opened_at"),
                "last_seen_at": incident.get("last_seen_at"),
            }
        )

    opening_reason = str(incident.get("opening_reason") or "").strip()
    if opening_reason:
        append_entry(
            {
                "kind": "opening_reason",
                "summary": opening_reason,
                "opened_at": incident.get("opened_at"),
                "last_seen_at": incident.get("last_seen_at"),
            }
        )

    affected_contexts = list(incident.get("affected_contexts") or [])
    if affected_contexts:
        append_entry(
            {
                "kind": "affected_contexts",
                "summary": f"Contextos afetados na abertura: {' | '.join(str(item) for item in affected_contexts[:6])}",
                "opened_at": incident.get("opened_at"),
                "last_seen_at": incident.get("last_seen_at"),
            }
        )

    return entries[:limit]


def build_stale_or_historical_evidence_entries(
    incident: Optional[dict[str, Any]],
    *,
    host: Optional[dict[str, Any]] = None,
    recent_operational_signals: Optional[list[dict[str, Any]]] = None,
    recent_syslog: Optional[list[dict[str, Any]]] = None,
    limit: int = 6,
) -> list[dict[str, Any]]:
    if not incident:
        return []

    incident_last_seen = parse_ai_timestamp(incident.get("last_seen_at")) or parse_ai_timestamp(incident.get("opened_at"))
    latest_recent_ts = max(
        (
            item
            for item in [
                parse_ai_timestamp((host or {}).get("last_activity_at")),
                parse_ai_timestamp((host or {}).get("last_collection_at")),
                *(parse_ai_timestamp(item.get("last_seen")) for item in list(recent_operational_signals or [])),
                *(parse_ai_timestamp(item.get("ts")) for item in list(recent_syslog or [])),
            ]
            if item is not None
        ),
        default=None,
    )
    if not incident_last_seen or not latest_recent_ts:
        return []
    if (latest_recent_ts - incident_last_seen).total_seconds() <= 300:
        return []

    entries = [
        {
            "kind": "stale_notice",
            "summary": (
                "O incidente aberto permanece ativo, mas a evidência que sustentou a abertura é anterior "
                "à janela recente e não se repete integralmente agora."
            ),
            "opened_at": incident.get("opened_at"),
            "last_seen_at": incident.get("last_seen_at"),
        }
    ]
    entries.extend(build_incident_supporting_evidence_entries(incident, limit=max(limit - 1, 0)))
    return entries[:limit]

def trim_ai_items(items: list[Any], limit: int) -> list[Any]:
    if limit <= 0:
        return []
    return list(items[:limit])


def normalize_chat_message(message: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(message or ""))
    normalized = normalized.encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"[^a-zA-Z0-9\s]", " ", normalized).lower()
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def is_greeting_message(message: str) -> bool:
    normalized = normalize_chat_message(message)
    if not normalized:
        return False

    greeting_values = {
        "oi",
        "ola",
        "eai",
        "e ai",
        "fala",
        "opa",
        "salve",
        "blz",
        "beleza",
        "tudo bem",
        "bom dia",
        "boa tarde",
        "boa noite",
        "oi netguard",
        "ola netguard",
        "eai netguard",
        "fala netguard",
    }

    if normalized in greeting_values:
        return True

    tokens = normalized.split()
    if len(tokens) <= 3 and tokens and tokens[0] in {"oi", "ola", "eai", "fala", "opa", "salve", "blz", "beleza"}:
        return True
    if len(tokens) <= 4 and tokens[:2] in (["bom", "dia"], ["boa", "tarde"], ["boa", "noite"], ["e", "ai"]):
        return True

    return False


def build_greeting_chat_reply(context: dict[str, Any]) -> str:
    host_context = context.get("host_context") or {}
    incident_context = context.get("incident_context") or {}
    host_name = ((host_context.get("host") or {}).get("name")) if isinstance(host_context, dict) else None
    incident_title = ((incident_context.get("incident") or {}).get("title")) if isinstance(incident_context, dict) else None

    if host_name:
        return (
            f"Oi! Posso te ajudar com o estado do host {host_name}, incidentes, sinais recentes, dashboards ou com dúvidas sobre o próprio NetGuard."
        )
    if incident_title:
        return (
            f"Oi! Posso te ajudar a interpretar o incidente \"{incident_title}\", revisar evidências ou explicar o contexto operacional do NetGuard."
        )

    return (
        "Oi! Posso te ajudar com o estado do ambiente, hosts, incidentes, dashboards ou com dúvidas sobre o próprio NetGuard."
    )

def build_fast_operational_chat_reply(message: str, context: dict[str, Any]) -> Optional[str]:
    question_kind = str(context.get("question_kind") or "operational").strip().lower()
    if question_kind in {"conceptual", "product", "comparison", "presentation", "article", "network", "greeting"}:
        return None

    brief = context.get("active_operational_brief") or {}
    assessment = context.get("operational_assessment") or {}
    if not brief and not assessment:
        return None

    normalized = normalize_chat_message(message)
    host_name = str(brief.get("host_affectado") or assessment.get("focus_host") or "host em foco").strip()
    incident = brief.get("focused_incident") or {}
    incident_type = incident.get("incident_type") if isinstance(incident, dict) else None
    if not incident_type and isinstance(assessment.get("incident"), dict):
        incident_type = assessment.get("incident", {}).get("incident_type")

    if any(token in normalized for token in ("causa", "raiz", "por que", "porque", "o que fazer", "agir", "agora", "pr?ximo", "proximo")):
        pass

    state = str(brief.get("estado_atual") or assessment.get("state") or "").strip()
    impact = str(brief.get("impacto_provavel") or brief.get("possivel_impacto") or assessment.get("impact") or "Impacto n?o definido no contexto atual.").strip()
    priority = str(brief.get("priority") or assessment.get("priority") or "").strip()
    actions = dedupe_text_items(list(brief.get("acoes_recomendadas") or []) or list(assessment.get("runbooks") or []))
    commands = dedupe_text_items(list(brief.get("comandos_validacao") or []) or list(assessment.get("runbooks") or []))
    recent_evidence = dedupe_text_items(list(brief.get("recent_evidence") or []) or list(assessment.get("facts") or []))
    limits = dedupe_text_items(list(brief.get("limitacoes") or []) + list(assessment.get("limits") or []))

    evidence: list[str] = []
    for item in list(brief.get("evidencias_abertura") or [])[:4]:
        text_item = str(item or "").strip()
        if text_item and text_item not in evidence:
            evidence.append(text_item)
    for item in list(brief.get("evidencias_recuperacao") or [])[:2]:
        text_item = str(item or "").strip()
        if text_item and text_item not in evidence:
            evidence.append(text_item)
    for item in recent_evidence[:3]:
        if item and item not in evidence:
            evidence.append(item)

    hypothesis = str(brief.get("causa_provavel") or (assessment.get("inferences") or [None])[0] or "N?o h? evid?ncias suficientes para concluir a causa raiz.").strip()

    lines: list[str] = []
    lines.append("Fatos observados:")
    if state:
        lines.append(f"- Estado atual: {state}")
    if host_name:
        lines.append(f"- Host afetado: {host_name}")
    if brief.get("ip"):
        lines.append(f"- IP: {brief.get('ip')}")
    if brief.get("severidade"):
        lines.append(f"- Severidade: {brief.get('severidade')}")
    if brief.get("status_snmp"):
        lines.append(f"- Status SNMP: {brief.get('status_snmp')}")
    if evidence:
        lines.extend(f"- {item}" for item in evidence[:5])
    else:
        lines.append("- N?o h? evid?ncias suficientes para concluir a causa raiz.")

    lines.append("Hip?tese prov?vel:")
    lines.append(f"- {hypothesis}")

    lines.append("Impacto:")
    lines.append(f"- {impact}")

    lines.append("O que fazer agora:")
    if actions:
        lines.extend(f"- {item}" for item in actions[:5])
    else:
        lines.append("- N?o h? a??es adicionais definidas no contexto atual.")

    lines.append("Comandos recomendados:")
    if commands:
        lines.extend(f"- `{item}`" for item in commands[:6])
    else:
        lines.append("- N?o h? comandos adicionais definidos no contexto atual.")

    lines.append("Limita??es da an?lise:")
    if limits:
        lines.extend(f"- {item}" for item in limits[:3])
    else:
        lines.append("- N?o h? limita??es adicionais registradas.")

    if not any(token in normalized for token in ("causa", "raiz", "o que fazer", "agora", "por que", "porque")) and priority:
        lines.insert(3, f"- Prioridade: {priority}")

    return "\n\n".join(lines)


def build_fast_conceptual_chat_reply(message: str, context: dict[str, Any]) -> Optional[str]:
    normalized = normalize_chat_message(message)
    question_kind = str(context.get("question_kind") or "").strip().lower()
    if question_kind not in {"conceptual", "product", "comparison", "presentation", "article", "network"}:
        return None

    if "mttr" in normalized or "tempo medio de reparo" in normalized or "tempo medio de resolucao" in normalized or "tempo medio para resolver" in normalized:
        return (
            "MTTR é o tempo médio para recuperar ou resolver um incidente. No NetGuard, a forma correta de calcular e usar a linha do tempo do incidente é: "
            "`MTTR = média(resolved_at - first_detected_at)` ou, quando `first_detected_at` não existir, `média(resolved_at - opened_at)`.\n\n"
            "Sobre comparação com Zabbix ou SolarWinds: eu não afirmaria uma média melhor sem um experimento controlado com os mesmos ativos, falhas e critério de resolução. "
            "Para o artigo, a resposta honesta e forte é dizer que o NetGuard registra os timestamps necessários para medir MTTR no MVP e que a comparação com ferramentas comerciais deve ser feita como maturidade funcional/metodológica, não como promessa de desempenho superior sem base histórica."
        )

    if "mttd" in normalized or "tempo medio de deteccao" in normalized or "tempo medio para detectar" in normalized:
        return (
            "MTTD é o tempo médio até detectar uma falha. No NetGuard, ele pode ser medido quando existe um instante conhecido da falha e o instante em que o incidente foi criado: "
            "`MTTD = média(first_detected_at - failure_started_at)`. Se o início real da falha não for conhecido, o projeto pode medir um MTTD aproximado usando o primeiro sinal recebido por ICMP, SNMP ou syslog.\n\n"
            "No artigo, isso deve aparecer como métrica de validação do fluxo de detecção, deixando claro se o valor vem de simulação controlada ou de observação real."
        )

    if "mtbf" in normalized:
        return (
            "MTBF é o tempo médio entre falhas. Ele é diferente de MTTR: MTBF mede confiabilidade ao longo do tempo, enquanto MTTR mede velocidade de recuperação. "
            "O NetGuard pode apoiar esse cálculo a partir do histórico de incidentes por ativo, mas só dá para afirmar uma média real depois de acumular amostras suficientes no período avaliado."
        )

    if "sla" in normalized or "disponibilidade" in normalized:
        return (
            "SLA, no contexto do NetGuard, pode ser apresentado como disponibilidade operacional por host ou grupo. A fórmula mais simples é: "
            "`disponibilidade = amostras_up / amostras_totais * 100`, usando a métrica `host.alive` no período analisado.\n\n"
            "Para o TCC, isso é bom porque conecta coleta ICMP, histórico de métricas e relatório. A ressalva é que disponibilidade calculada por ping mostra alcance do host, não necessariamente qualidade completa de todos os serviços daquele ativo."
        )

    anomaly_speed_terms = (
        "anomalia",
        "anomalias",
        "prever",
        "previsao",
        "previsoes",
        "detectar",
        "deteccao",
        "detecção",
    )
    percentage_terms = (
        "porcentagem",
        "percentual",
        "mais rapido",
        "mais rápida",
        "mais rapida",
        "mais rápido",
        "quanto mais",
    )
    if any(term in normalized for term in anomaly_speed_terms) and (
        any(term in normalized for term in percentage_terms)
        or "zabbix" in normalized
        or "solarwinds" in normalized
    ):
        return (
            "Eu não cravaria um percentual real dizendo que o NetGuard detecta ou prevê anomalias X% mais rápido que Zabbix/SolarWinds sem um benchmark controlado. "
            "Esse número depende do intervalo de coleta, thresholds/triggers configurados, volume de histórico, tipo de falha e critério de abertura do incidente.\n\n"
            "A forma correta para o artigo é calcular assim: `ganho_% = ((tempo_referência - tempo_netguard) / tempo_referência) * 100`. "
            "Exemplo de laboratório: se o NetGuard detecta em 15s e a ferramenta de referência do experimento detecta em 60s, o ganho é `((60 - 15) / 60) * 100 = 75%` mais rápido naquele cenário. "
            "Isso pode ser apresentado como potencial medido no lab, não como vantagem universal sobre Zabbix ou SolarWinds.\n\n"
            "Para previsão de anomalias, eu separaria a métrica: use `lead time`, ou seja, quantos segundos/minutos antes do incidente o NetGuard sinalizou risco. "
            "Se quiser transformar em porcentagem, compare o lead time do NetGuard contra o lead time da ferramenta de referência no mesmo teste."
        )

    if "stp" in normalized or "loop guard" in normalized or "loop l2" in normalized or "broadcast storm" in normalized or "mac flapping" in normalized:
        return (
            "Em rede L2, STP/RSTP evita que caminhos redundantes virem loop. Loop Guard ajuda a impedir que uma porta que deveria bloquear passe indevidamente para forwarding quando deixa de receber BPDUs. "
            "Quando STP/Loop Guard falham ou estão desativados, os sintomas comuns são broadcast storm, MAC flapping, perda de pacotes, alta latência e instabilidade de portas.\n\n"
            "No NetGuard, esse tipo de caso é tratado correlacionando syslog, sinais de storm, MAC flapping, eventos STP e loop_risk. A leitura correta é: porta `Up` não significa recuperação; recuperação precisa de evidência como bloqueio por STP/Loop Guard, fim de storm/flapping ou resolução manual confirmada."
        )

    if "switch" in normalized and "rede" in normalized:
        return (
            "Um switch de rede é um equipamento que conecta dispositivos dentro de uma LAN e encaminha os quadros para a porta correta usando a tabela MAC. "
            "Na prática, ele permite que computadores, servidores, APs e outros equipamentos conversem entre si de forma mais eficiente do que em uma rede compartilhada simples.\n\n"
            "No NetGuard, um switch pode ser acompanhado por ICMP, SNMP e syslog: o ICMP mostra disponibilidade e latência, o SNMP traz interfaces, tráfego, erros e descartes, e o syslog ajuda a enxergar eventos como storm, flap, link up/down e sinais de risco de loop."
        )

    if "snmp" in normalized:
        return (
            "SNMP é um protocolo usado para coletar informações de equipamentos de rede e servidores, como status de interfaces, contadores de tráfego, erros, descartes e dados básicos do sistema. "
            "No NetGuard, ele é uma das bases para transformar telemetria bruta em visão operacional por host, anomalias e incidentes."
        )

    if "icmp" in normalized and "tcp" in normalized:
        return (
            "ICMP e TCP check se complementam no monitoramento. ICMP responde à pergunta \"o host está alcançável e com qual latência/perda?\"; TCP check responde \"um serviço específico está aceitando conexão naquela porta?\".\n\n"
            "No NetGuard, ICMP é melhor para disponibilidade, RTT e perda. TCP check é melhor para validar serviços como HTTPS, SSH, banco ou APIs. Um host pode responder ping e ainda estar com o serviço crítico fora."
        )

    if "icmp" in normalized or "ping" in normalized:
        return (
            "ICMP, na prática do monitoramento, é usado principalmente para verificar alcance, latência e perda de pacotes por ping. "
            "Ele não prova que todos os serviços do host estão saudáveis, mas é excelente como sinal rápido de disponibilidade e degradação de rede.\n\n"
            "No NetGuard, ICMP ajuda a alimentar disponibilidade, RTT, perda e incidentes de host indisponível ou instável."
        )

    if "tcp" in normalized or "udp" in normalized or "porta" in normalized:
        return (
            "Checks TCP validam se um serviço específico aceita conexão em uma porta, por exemplo 22/SSH, 80/HTTP, 443/HTTPS ou 5432/PostgreSQL. "
            "Isso complementa o ICMP: um host pode responder ping e ainda assim estar com um serviço crítico fora.\n\n"
            "UDP é mais difícil de validar de forma genérica porque nem sempre há handshake. Para monitoramento MVP, TCP checks e ICMP costumam dar uma base operacional mais previsível."
        )

    if "vlan" in normalized or "camada 2" in normalized or "l2" in normalized:
        return (
            "VLAN separa domínios de broadcast na camada 2. Isso melhora organização, segurança e controle de tráfego, mas também exige cuidado com trunk, STP, loops e propagação de broadcast.\n\n"
            "No NetGuard, eventos L2 como MAC flapping, broadcast storm, STP e loop_risk são bons sinais para explicar instabilidade em switches."
        )

    if "cidr" in normalized or "subrede" in normalized or "sub rede" in normalized:
        return (
            "CIDR é a forma de representar rede e máscara, como `192.168.56.0/24`. O `/24` indica 24 bits de rede, deixando 8 bits para hosts, ou seja, normalmente 254 endereços utilizáveis.\n\n"
            "No contexto do NetGuard, uma faixa CIDR é útil para discovery, cadastro de ativos e organização do laboratório."
        )

    if "syslog" in normalized:
        return (
            "Syslog é o fluxo de eventos que equipamentos e sistemas enviam para registrar mudanças e problemas operacionais. "
            "No NetGuard, esses eventos ajudam a detectar sinais como interface flap, broadcast storm, MAC flapping e ausência de logs quando um host deveria estar enviando syslog."
        )

    if (
        "rota padrao" in normalized
        or "rota padrão" in normalized
        or "default route" in normalized
        or "sumarizacao" in normalized
        or "sumarização" in normalized
        or "route summarization" in normalized
    ):
        return (
            "Rota padrão é o caminho usado quando não existe uma rota mais específica para o destino; sumarização de rotas é a técnica de agrupar várias redes em um prefixo maior para reduzir tabelas e anúncios de roteamento.\n\n"
            "Isso é conceito geral de redes. No NetGuard, hoje esse tema pode aparecer como apoio de troubleshooting e documentação, mas não como uma função implementada de roteamento dinâmico ou gestão de rotas."
        )

    if "artigo" in normalized or "tcc" in normalized or "banca" in normalized:
        return (
            "Para o artigo/TCC, eu explicaria o NetGuard como uma plataforma proativa de monitoramento e rastreabilidade de incidentes em redes corporativas. "
            "O ponto central não é dizer que ele substitui Zabbix ou SolarWinds, e sim mostrar que ele integra coleta, métricas, syslog, incidentes, alertas, dashboards e IA contextual em um fluxo demonstrável.\n\n"
            "As métricas mais fortes para defender o projeto são disponibilidade, tempo de detecção, MTTR quando houver resolução registrada, quantidade de incidentes rastreados, alertas enviados/suprimidos e qualidade das evidências por incidente."
        )

    if "dashboard" in normalized or "grafana" in normalized:
        return (
            "No NetGuard, dashboards servem para visualizar a telemetria e os eventos de forma operacional. "
            "O dashboard do host de rede mostra disponibilidade, RTT, perda ICMP, tráfego por interface, erros, descartes, loop risk, syslog recente, anomalias e incidentes relacionados ao ativo selecionado."
        )

    if "incidente" in normalized:
        return (
            "Um incidente no NetGuard é um registro operacional consolidado de algo que merece atenção, como host down, silêncio de coleta, risco de loop ou anomalias relevantes. "
            "A ideia é evitar que o operador precise juntar manualmente ping, SNMP, syslog e previsões para entender o que está acontecendo."
        )

    if "coleta" in normalized:
        return (
            "A área Coleta de dados organiza como o NetGuard busca sinais dos ativos monitorados. "
            "Ela envolve ICMP, SNMP, syslog e políticas de intervalo, timeout e tentativas, para que a plataforma saiba quando um host está saudável, indisponível ou sem telemetria recente."
        )

    if "netguard" in normalized or question_kind == "product":
        product_context = context.get("product_context") or PRODUCT_AI_CONTEXT
        capabilities = list(product_context.get("current_capabilities") or [])[:5]
        capability_text = "; ".join(str(item) for item in capabilities) or "monitoramento, incidentes, dashboards e insights operacionais"
        return (
            f"O NetGuard é uma plataforma de monitoramento orientada por host, com telemetria, eventos, incidentes, dashboards e apoio contextual por IA. "
            f"No estado atual, ele cobre principalmente {capability_text}.\n\n"
            "Ele se aproxima conceitualmente de ferramentas como Zabbix e SolarWinds em recursos de monitoramento, alertas, dashboards, Media Types e retenção, mas sem afirmar paridade total com suítes enterprise maduras. O foco atual é entregar um fluxo mais guiado para investigar hosts, sinais recentes e incidentes no laboratório."
        )

    return None


def build_domain_chat_fallback_reply(message: str, context: dict[str, Any], reason: str) -> Optional[str]:
    normalized = normalize_chat_message(message)
    question_kind = str(context.get("question_kind") or "").strip().lower()
    if question_kind not in {"conceptual", "product", "comparison", "presentation", "article", "network"}:
        return None

    if question_kind == "article":
        return (
            "O modelo local demorou para responder, então vou responder pelo conhecimento técnico configurado no NetGuard.\n\n"
            "Para o artigo/TCC, trate o NetGuard como uma plataforma acadêmica aplicada de monitoramento proativo e rastreabilidade. "
            "As perguntas sobre MTTR, MTTD, SLA, disponibilidade, alertas, incidentes e comparação com Zabbix/SolarWinds devem ser respondidas com fórmula, dado medido quando existir e ressalva quando não houver experimento controlado. "
            "Exemplo: se a pergunta for MTTR, use `média(resolved_at - first_detected_at)` e deixe claro que não dá para afirmar desempenho superior a suítes comerciais sem amostra histórica comparável."
        )

    if question_kind == "network":
        if "dns" in normalized:
            return (
                "DNS traduz nomes para endereços IP. Em troubleshooting, falha de DNS pode parecer queda de aplicação mesmo quando rede e servidor estão acessíveis por IP. "
                "No NetGuard, isso pode virar check complementar de serviço, porque ICMP sozinho não valida resolução de nomes."
            )
        if "dhcp" in normalized:
            return (
                "DHCP entrega configuração IP automaticamente, incluindo IP, máscara, gateway e DNS. "
                "Problemas de DHCP costumam aparecer como hosts sem IP válido, gateway incorreto ou perda de conectividade após renovação de lease."
            )
        if "gateway" in normalized or "firewall" in normalized:
            return (
                "Gateway é o ponto de saída para outras redes; firewall aplica controle de tráfego entre zonas, redes ou serviços. "
                "Quando um host responde localmente mas falha fora da sub-rede, eu investigaria gateway, rota, ACL/firewall e NAT antes de concluir falha do servidor."
            )
        return (
            "O modelo local demorou para responder, mas a pergunta foi classificada como redes. "
            "Eu posso responder conceitos de ICMP, TCP/UDP, SNMP, syslog, VLAN, STP, loop L2, CIDR, gateway, DNS, DHCP, latência, perda e troubleshooting, conectando com o NetGuard quando fizer sentido.\n\n"
            "Regra importante: para teoria de redes eu posso usar conhecimento técnico geral; para dizer o estado real do ambiente eu preciso de evidências do NetGuard, como métricas, syslog, incidentes ou dashboard."
        )

    if question_kind == "comparison":
        return (
            "O modelo local demorou para responder, então vou usar a regra segura de comparação: o NetGuard pode ser comparado a Zabbix/SolarWinds por maturidade funcional, fluxo operacional e recursos demonstráveis, mas não como equivalência total.\n\n"
            "A comparação correta destaca o que o NetGuard entrega hoje: coleta, dashboards, incidentes, alertas, Media Types, loop_risk, syslog e IA contextual. O que ainda for enterprise, como HA, RBAC forte, escalação avançada, mapas completos e NetPath real, deve entrar como roadmap."
        )

    if question_kind in {"product", "presentation", "conceptual"}:
        return (
            "O modelo local demorou para responder, então vou responder com o contexto estruturado do produto. "
            "O NetGuard deve ser explicado como uma plataforma de monitoramento de redes com coleta ICMP/SNMP/syslog, incidentes rastreáveis, dashboards, alertas e IA contextual. "
            "Quando a pergunta for de banca ou artigo, a resposta precisa separar: o que está implementado, o que foi validado no laboratório e o que é roadmap."
        )

    return f"Falha tecnica reportada: {reason}"


def build_ai_unavailable_chat_reply(message: str, context: dict[str, Any], reason: str) -> str:
    fast_reply = build_fast_conceptual_chat_reply(message, context)
    if fast_reply:
        return fast_reply

    domain_reply = build_domain_chat_fallback_reply(message, context, reason)
    if domain_reply:
        return domain_reply

    assessment = context.get("operational_assessment") or {}
    state = str(assessment.get("state") or "").strip()
    impact = str(assessment.get("impact") or "").strip()
    priority = str(assessment.get("priority") or "").strip()
    facts = list(assessment.get("facts") or [])

    lines = [
        "O modelo local de IA não respondeu dentro do tempo limite, então vou usar o contexto estruturado já carregado pelo NetGuard sem inventar conclusões.",
    ]
    if state:
        lines.append(f"Estado atual: {state}")
    if impact:
        lines.append(f"Impacto provável: {impact}")
    if priority:
        lines.append(f"Prioridade: {priority}.")
    if facts:
        lines.append("Sinais principais: " + "; ".join(str(item) for item in facts[:3]) + ".")
    if len(lines) == 1:
        lines.append(f"Falha tecnica reportada: {reason}")

    return "\n\n".join(lines)


def classify_chat_question(message: str) -> str:
    if is_greeting_message(message):
        return "greeting"

    normalized = normalize_chat_message(message)
    if not normalized:
        return "operational"

    operational_keywords = [
        "o que esta acontecendo",
        "o que aconteceu",
        "estado atual",
        "situacao atual",
        "principal risco",
        "risco atual",
        "o que eu faco",
        "o que devo fazer",
        "o que fazer agora",
        "acao imediata",
        "causa raiz",
        "causa provavel",
        "evidencias",
        "alerta aberto",
        "incidente aberto",
        "host em foco",
    ]
    if any(keyword in normalized for keyword in operational_keywords):
        return "operational"

    comparison_keywords = [
        "zabbix",
        "solarwinds",
        "compar",
        "diferencial",
        "por que usar",
        "por que escolher",
        "vantagem",
        "melhor que",
        "rede grande",
        "escalável",
        "escalavel",
    ]
    presentation_keywords = [
        "banca",
        "tcc",
        "apresentação",
        "apresentacao",
        "demonstrar",
        "demo",
        "explicar para",
        "apresentar",
    ]
    article_keywords = [
        "artigo",
        "tcc",
        "monografia",
        "trabalho academico",
        "metodologia",
        "validacao",
        "resultado",
        "resultados",
        "hipotese",
        "objetivo geral",
        "objetivo especifico",
        "referencial teorico",
        "mttr",
        "mttd",
        "mtta",
        "mtbf",
        "sla",
        "disponibilidade",
        "indicador",
        "indicadores",
        "metricas",
        "tempo medio",
    ]
    network_keywords = [
        "redes de computadores",
        "rede local",
        "rede corporativa",
        "lan",
        "wan",
        "camada 2",
        "camada 3",
        "l2",
        "l3",
        "vlan",
        "stp",
        "rstp",
        "loop guard",
        "broadcast storm",
        "mac flapping",
        "icmp",
        "tcp",
        "udp",
        "snmp",
        "syslog",
        "traceroute",
        "latencia",
        "jitter",
        "perda de pacote",
        "roteador",
        "firewall",
        "sub rede",
        "subrede",
        "cidr",
        "gateway",
        "dns",
        "dhcp",
    ]
    conceptual_keywords = [
        "o que e",
        "qual a diferenca",
        "qual e a diferenca",
        "switch de rede",
        "o que é",
        "o que voce pode fazer",
        "o que você pode fazer",
        "para que serve",
        "qual a diferença",
        "qual é a diferença",
        "como funciona",
        "como usa ia",
        "como o netguard usa ia",
        "que tipos de dispositivos",
        "tipos de hosts",
        "coleta via snmp",
        "o que monitora",
        "o que faz",
        "como pode evoluir",
    ]
    product_keywords = [
        "switch",
        "netguard",
        "produto",
        "projeto",
        "coleta de dados",
        "monitoramento",
        "relatórios",
        "insights",
        "ia",
        "dashboards",
        "incidentes e insights",
        "tipos de hosts",
        "monitora hoje",
        "coleta via snmp",
        "o que monitora",
        "como funciona",
        "marcas",
        "dispositivos",
        "templates",
        "grupos de hosts",
        "host groups",
        "rede corporativa",
        "roadmap",
        "evoluir como produto",
        "foco atual",
        "diferencial do netguard",
        "valor",
    ]

    if any(keyword in normalized for keyword in comparison_keywords):
        return "comparison"
    if any(keyword in normalized for keyword in presentation_keywords):
        return "presentation"
    if any(keyword in normalized for keyword in article_keywords):
        return "article"
    if any(keyword in normalized for keyword in conceptual_keywords):
        return "conceptual"
    if any(keyword in normalized for keyword in network_keywords):
        return "network"
    if any(keyword in normalized for keyword in product_keywords):
        return "product"
    return "operational"


def classify_chat_intent(message: str) -> str:
    if is_greeting_message(message):
        return "greeting"

    normalized = normalize_chat_message(message)
    if not normalized:
        return "status_atual"

    operational_intent_keywords = {
        "status_atual": [
            "o que esta acontecendo",
            "o que aconteceu",
            "estado atual",
            "situacao atual",
            "qual o estado",
            "o que o netguard detectou",
            "o que aconteceu no",
            "qual interface esta com problema",
        ],
        "impacto": [
            "isso e grave",
            "a rede vai parar",
            "vai parar",
            "qual o impacto",
            "qual e o impacto",
            "qual a prioridade",
            "qual e a prioridade",
            "posso ignorar",
            "urgente",
        ],
        "acao_imediata": [
            "o que eu faco agora",
            "o que devo fazer agora",
            "o que devo fazer",
            "o que faco primeiro",
            "qual o primeiro passo",
            "como agir",
            "acao imediata",
        ],
        "causa_provavel": [
            "qual e a causa provavel",
            "causa provavel",
            "causa raiz",
            "origem provavel",
            "por que isso aconteceu",
            "o que causou",
        ],
        "evidencias": [
            "como voce sabe disso",
            "como voce sabe",
            "quais evidencias",
            "o que sustenta",
            "como chegou nisso",
            "o que ainda nao da para afirmar",
            "o que ainda nao da para concluir",
        ],
    }

    if any(keyword in normalized for keyword in ("zabbix", "solarwinds", "compar", "diferencial", "melhor que")):
        return "comparison"
    if any(keyword in normalized for keyword in ("banca", "tcc", "apresentacao", "demo", "gestor", "tecnicamente")):
        return "presentation"
    if any(
        keyword in normalized
        for keyword in (
            "artigo",
            "tcc",
            "metodologia",
            "validacao",
            "mttr",
            "mttd",
            "mtta",
            "mtbf",
            "sla",
            "disponibilidade",
            "indicador",
            "metricas",
        )
    ):
        return "article"

    for intent, keywords in operational_intent_keywords.items():
        if any(keyword in normalized for keyword in keywords):
            return intent

    question_kind = classify_chat_question(message)
    if question_kind in {"product", "comparison", "presentation", "conceptual", "article", "network", "greeting"}:
        return question_kind
    return "status_atual"


def build_response_contract_for_intent(intent: str) -> Optional[dict[str, Any]]:
    normalized = str(intent or "").strip().lower()
    if normalized not in OPERATIONAL_CHAT_INTENTS:
        return None
    contract = OPERATIONAL_RESPONSE_CONTRACTS.get(normalized) or OPERATIONAL_RESPONSE_CONTRACTS["status_atual"]
    return {
        "intent": normalized,
        "label": contract["label"],
        "objective": contract["objective"],
        "order": list(contract["order"]),
        "mandatory_topics": [
            "estado atual",
            "impacto provável",
            "prioridade",
            "ação recomendada",
            "evidências",
            "limites e incertezas",
        ],
    }


def render_response_contract_digest(contract: Optional[dict[str, Any]]) -> str:
    if not contract:
        return ""
    lines = [
        "Contrato de resposta para esta pergunta:",
        f"- Intenção: {contract.get('label') or '-'}",
        f"- Objetivo: {contract.get('objective') or '-'}",
        f"- Ordem sugerida: {' > '.join(str(item) for item in contract.get('order') or [])}",
        f"- Tópicos obrigatórios: {' | '.join(str(item) for item in contract.get('mandatory_topics') or [])}",
    ]
    return "\n".join(lines)


def build_product_ai_context(cur) -> dict[str, Any]:
    templates_enabled: list[dict[str, Any]] = []
    templates_planned: list[str] = []

    if has_monitoring_templates_schema(cur):
        for template in list_monitoring_template_records(cur):
            record = {
                "name": template["name"],
                "asset_type": template["asset_type"],
                "vendor": template["vendor"],
                "family": template["family"],
                "summary": template["summary"],
            }
            if template["enabled"]:
                templates_enabled.append(record)
            else:
                templates_planned.append(template["name"])

    return {
        **PRODUCT_AI_CONTEXT,
        "enabled_templates": templates_enabled,
        "planned_templates": templates_planned or PRODUCT_AI_CONTEXT["planned_vendor_targets"],
        "dashboard_keys": [
            {
                "key": key,
                "title": item["title"],
                "kind": item["kind"],
                "description": item["description"],
            }
            for key, item in GRAFANA_DASHBOARD_REGISTRY.items()
        ],
    }


def build_environment_ai_context(cur, *, hours: int = 24) -> dict[str, Any]:
    to_ts = datetime.now(timezone.utc)
    from_ts = to_ts - timedelta(hours=hours)
    groups_ready = has_host_groups_schema(cur)
    templates_ready = has_monitoring_templates_schema(cur)
    collection_policy_ready = has_assets_collection_policy_schema(cur)

    query = (
        f"SELECT {', '.join(build_host_select_parts(groups_ready, templates_ready, collection_policy_ready))} "
        f"FROM {ASSETS_TABLE} a"
    )
    if groups_ready:
        query += " LEFT JOIN host_groups g ON g.id = a.group_id"
    if templates_ready:
        query += " LEFT JOIN monitoring_templates t ON t.id = a.template_id"
    query += " ORDER BY a.id LIMIT 20"

    cur.execute(query)
    hosts = [
        host_row_to_dict(row, groups_ready, templates_ready, collection_policy_ready)
        for row in cur.fetchall()
    ]
    hosts = attach_host_operational_state(cur, hosts, from_ts, to_ts)

    enabled_hosts = [host for host in hosts if bool(host.get("enabled", True))]
    enabled_hosts.sort(key=host_operational_priority, reverse=True)
    focus_hosts = [compact_host_snapshot_for_ai(host) for host in enabled_hosts[:4]]

    cur.execute(
        f"""
        SELECT
            COUNT(*) AS total_hosts,
            COUNT(*) FILTER (WHERE enabled) AS active_hosts,
            COUNT(*) FILTER (WHERE NOT enabled) AS inactive_hosts
        FROM {ASSETS_TABLE}
        """
    )
    host_counts = cur.fetchone()

    cur.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE LOWER(i.status) = 'open') AS open_incidents,
            COUNT(*) FILTER (WHERE LOWER(i.status) = 'open' AND LOWER(i.incident_type) = 'loop_risk') AS open_loop_risk
        FROM incidents i
        LEFT JOIN assets a ON a.id = i.asset_id
        WHERE COALESCE(a.enabled, TRUE) = TRUE
        """
    )
    incident_counts = cur.fetchone()

    recent_incidents = select_incident_records(cur, from_ts=from_ts, to_ts=to_ts, limit=4, active_hosts_only=True)
    active_incidents = select_incident_records(cur, status="open", limit=6, active_hosts_only=True)
    recent_syslog = select_syslog_records(cur, from_ts=from_ts, to_ts=to_ts, limit=4)
    recent_predictions = select_prediction_records(cur, from_ts=from_ts, to_ts=to_ts, limit=4)

    ops_dashboard = build_grafana_dashboard(
        "ops_overview",
        owner_type="ops",
        owner_id=None,
        from_ts=from_ts,
        to_ts=to_ts,
    )

    return {
        "scope": "environment",
        "time_window": {
            "from": to_iso(from_ts),
            "to": to_iso(to_ts),
            "hours": hours,
        },
        "environment": {
            "total_hosts": int(host_counts[0] or 0),
            "active_hosts": int(host_counts[1] or 0),
            "inactive_hosts": int(host_counts[2] or 0),
            "open_incidents": int(incident_counts[0] or 0),
            "open_loop_risk": int(incident_counts[1] or 0),
        },
        "priority_hosts": focus_hosts,
        "active_incidents": trim_ai_items([compact_incident_for_ai(item) for item in active_incidents], 6),
        "recent_incidents": trim_ai_items([compact_incident_for_ai(item) for item in recent_incidents], 4),
        "recent_syslog": trim_ai_items([compact_syslog_for_ai(item) for item in recent_syslog], 4),
        "recent_predictions": trim_ai_items([compact_prediction_for_ai(item) for item in recent_predictions], 4),
        "dashboard_context": {
            "title": ops_dashboard["title"],
            "dashboard_key": ops_dashboard["dashboard_key"],
            "kind": ops_dashboard["kind"],
            "variables": ops_dashboard["variables"],
        },
    }


def resolve_chat_focus_context(
    cur,
    *,
    environment_context: dict[str, Any],
    host_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    hours: int = 24,
) -> dict[str, Any]:
    host_context = None
    incident_context = None
    focus_mode = "environment"
    focus_reason = "Contexto geral do ambiente."

    active_incident_records = select_incident_records(cur, status="open", limit=8, active_hosts_only=True)
    compact_active_incidents = sorted(
        trim_ai_items([compact_incident_for_ai(item) for item in active_incident_records], 8),
        key=active_incident_focus_priority,
        reverse=True,
    )

    if incident_id is not None:
        incident_context = build_incident_ai_context(cur, incident_id, hours=hours)
        focus_mode = "explicit_incident"
        focus_reason = "Incidente solicitado explicitamente na conversa."
        host_ref = (incident_context.get("host") or {}).get("id")
        if host_ref is not None:
            host_context = build_host_ai_context(cur, int(host_ref), hours=hours)

    if host_id is not None and incident_id is None:
        host_context = build_host_ai_context(cur, host_id, hours=hours)
        focus_mode = "explicit_host"
        focus_reason = "Host solicitado explicitamente na conversa."
        if incident_context is None:
            host_active_incidents = list(host_context.get("active_incidents") or [])
            lead_host_incident = host_active_incidents[0] if host_active_incidents else None
            if lead_host_incident and lead_host_incident.get("id") is not None:
                incident_context = build_incident_ai_context(cur, int(lead_host_incident["id"]), hours=hours)

    if host_context is None and incident_context is None:
        lead_incident = compact_active_incidents[0] if compact_active_incidents else None
        if lead_incident and lead_incident.get("id") is not None:
            incident_context = build_incident_ai_context(cur, int(lead_incident["id"]), hours=hours)
            host_ref = (incident_context.get("host") or {}).get("id")
            if host_ref is not None:
                host_context = build_host_ai_context(cur, int(host_ref), hours=hours)
            focus_mode = "active_incident"
            focus_reason = "Incidente aberto mais recente, severo e operacionalmente relevante selecionado como foco."

    if host_context is None:
        priority_hosts = list(environment_context.get("priority_hosts") or [])
        lead_host = priority_hosts[0] if priority_hosts else None
        if lead_host and lead_host.get("id") is not None:
            host_context = build_host_ai_context(cur, int(lead_host["id"]), hours=hours)
            if incident_context is None:
                lead_host_incident = next(iter(host_context.get("active_incidents") or []), None)
                if lead_host_incident and lead_host_incident.get("id") is not None:
                    incident_context = build_incident_ai_context(cur, int(lead_host_incident["id"]), hours=hours)
            if focus_mode == "environment":
                focus_mode = "top_risk_host"
                focus_reason = "Host com maior risco operacional atual do ambiente selecionado como foco."

    return {
        "host_context": host_context,
        "incident_context": incident_context,
        "active_incidents": compact_active_incidents,
        "focus_resolution": {
            "mode": focus_mode,
            "reason": focus_reason,
        },
    }


def build_chat_operational_assessment(
    *,
    focus_host_context: Optional[dict[str, Any]] = None,
    focus_incident_context: Optional[dict[str, Any]] = None,
    focus_reason: str = "",
    stale_or_historical_evidence: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    base = (
        (focus_host_context or {}).get("operational_assessment")
        or (focus_incident_context or {}).get("operational_assessment")
        or {}
    )
    host = (focus_host_context or {}).get("host") or (focus_incident_context or {}).get("host") or {}
    incident = (focus_incident_context or {}).get("incident") or {}

    facts = list(base.get("facts") or [])
    limits = list(base.get("limits") or [])
    state = str(base.get("state") or "Sem foco operacional definido.")

    host_name = host.get("name")
    if host_name:
        state = f"O principal foco operacional atual está em {host_name}. {state}"

    if incident:
        incident_type = incident.get("incident_type") or "operacional"
        severity = incident.get("severity") or "sem severidade"
        incident_title = incident.get("title") or "sem título"
        focus_fact = f"Foco principal do chat: incidente {incident_type} {severity} em {host_name or 'host sem identificação'}: {incident_title}."
        if focus_fact not in facts:
            facts.insert(0, focus_fact)

    if focus_reason:
        focus_limit = f"Resolução de foco do chat: {focus_reason}"
        if focus_limit not in limits:
            limits.insert(0, focus_limit)

    historical_entries = list(stale_or_historical_evidence or [])
    if historical_entries:
        historical_limit = "Parte da explicação depende de evidência histórica do incidente aberto, separada dos sinais mais recentes do host."
        if historical_limit not in limits:
            limits.insert(0, historical_limit)

    return {
        **base,
        "state": state,
        "facts": dedupe_text_items(facts)[:6],
        "limits": dedupe_text_items(limits)[:5],
    }


def build_chat_operational_assessment_contextual(
    *,
    focus_host_context: Optional[dict[str, Any]] = None,
    focus_incident_context: Optional[dict[str, Any]] = None,
    focus_reason: str = "",
    recent_operational_signals: Optional[list[dict[str, Any]]] = None,
    incident_supporting_evidence: Optional[list[dict[str, Any]]] = None,
    stale_or_historical_evidence: Optional[list[dict[str, Any]]] = None,
    low_relevance_signals: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    base = (
        (focus_host_context or {}).get("operational_assessment")
        or (focus_incident_context or {}).get("operational_assessment")
        or {}
    )
    host = (focus_host_context or {}).get("host") or (focus_incident_context or {}).get("host") or {}
    incident = (focus_incident_context or {}).get("incident") or {}
    recent_entries = list(recent_operational_signals or [])
    incident_entries = list(incident_supporting_evidence or [])
    historical_entries = list(stale_or_historical_evidence or [])
    low_entries = list(low_relevance_signals or [])

    facts: list[str] = []
    secondary_findings: list[str] = []
    supporting_signals: list[str] = []
    limits = list(base.get("limits") or [])
    inferences = list(base.get("inferences") or [])
    runbooks = list(base.get("runbooks") or [])
    state = str(base.get("state") or "Sem foco operacional definido.")
    impact = str(base.get("impact") or "Sem impacto operacional relevante definido.")
    priority = str(base.get("priority") or "monitorar")

    host_name = host.get("name")
    if host_name:
        state = f"O principal problema atual do ambiente está em {host_name}. {state}"

    if incident:
        incident_type = incident.get("incident_type") or "operacional"
        severity = incident.get("severity") or "sem severidade"
        incident_title = incident.get("title") or "sem título"
        facts.append(
            f"Incidente principal do ambiente: {incident_title} ({incident_type}, severidade {severity}) em {host_name or 'host sem identificação'}."
        )

    for item in recent_entries:
        summary = str(item.get("summary") or "").strip()
        if not summary:
            continue
        signal_type = str(item.get("signal_type") or "")
        if signal_type in {"loop_storm", "mac_flap"}:
            facts.append(summary)
        elif signal_type in {"interface_flap", "link_trap"}:
            secondary_findings.append(summary)
        else:
            supporting_signals.append(summary)

    for item in incident_entries:
        summary = str(item.get("summary") or "").strip()
        if not summary or summary in facts or summary in secondary_findings or summary in supporting_signals:
            continue
        kind = str(item.get("kind") or "")
        if kind in {"signal_context", "opening_reason"} and len(facts) < 6:
            facts.append(summary)
        else:
            supporting_signals.append(summary)

    if focus_reason:
        focus_limit = f"Resolução de foco do chat: {focus_reason}"
        if focus_limit not in limits:
            limits.insert(0, focus_limit)

    if historical_entries:
        historical_limit = "Parte da explicação depende de evidência histórica do incidente aberto, separada dos sinais mais recentes do host."
        if historical_limit not in limits:
            limits.insert(0, historical_limit)
        for item in historical_entries:
            summary = str(item.get("summary") or "").strip()
            if summary and summary not in supporting_signals:
                supporting_signals.append(summary)

    for item in low_entries:
        summary = str(item.get("summary") or "").strip()
        if summary and summary not in supporting_signals:
            supporting_signals.append(summary)

    return {
        **base,
        "state": state,
        "impact": impact,
        "priority": priority,
        "facts": dedupe_text_items(facts)[:6],
        "secondary_findings": dedupe_text_items(secondary_findings)[:6],
        "supporting_signals": dedupe_text_items(supporting_signals)[:6],
        "inferences": dedupe_text_items(inferences)[:4],
        "limits": dedupe_text_items(limits)[:5],
        "runbooks": runbooks[:4],
    }


def build_chat_ai_context(
    cur,
    *,
    message: str,
    host_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    hours: int = 24,
) -> dict[str, Any]:
    environment_context = build_environment_ai_context(cur, hours=hours)
    focus_bundle = resolve_chat_focus_context(
        cur,
        environment_context=environment_context,
        host_id=host_id,
        incident_id=incident_id,
        hours=hours,
    )
    host_context = focus_bundle.get("host_context")
    incident_context = focus_bundle.get("incident_context")
    question_kind = classify_chat_question(message)
    question_intent = classify_chat_intent(message)
    response_contract = build_response_contract_for_intent(question_intent)
    product_context = build_product_ai_context(cur)
    focus_host = (host_context or {}).get("host") if isinstance(host_context, dict) else None
    focus_incident = (incident_context or {}).get("incident") if isinstance(incident_context, dict) else None
    recent_operational_signals = list((host_context or {}).get("recent_operational_signals") or (incident_context or {}).get("recent_operational_signals") or [])
    incident_supporting_evidence = build_incident_supporting_evidence_entries(focus_incident, limit=8)
    stale_or_historical_evidence = list((host_context or {}).get("stale_or_historical_evidence") or (incident_context or {}).get("stale_or_historical_evidence") or [])
    low_relevance_signals = list((host_context or {}).get("low_relevance_signals") or (incident_context or {}).get("low_relevance_signals") or [])
    active_operational_brief = build_active_operational_brief(
        focus_host_context=host_context if isinstance(host_context, dict) else None,
        focus_incident_context=incident_context if isinstance(incident_context, dict) else None,
        focus_reason=str((focus_bundle.get("focus_resolution") or {}).get("reason") or ""),
        recent_operational_signals=recent_operational_signals,
        incident_supporting_evidence=incident_supporting_evidence,
        stale_or_historical_evidence=stale_or_historical_evidence,
        low_relevance_signals=low_relevance_signals,
    )
    operational_assessment = build_chat_operational_assessment_contextual(
        focus_host_context=host_context if isinstance(host_context, dict) else None,
        focus_incident_context=incident_context if isinstance(incident_context, dict) else None,
        focus_reason=str((focus_bundle.get("focus_resolution") or {}).get("reason") or ""),
        recent_operational_signals=recent_operational_signals,
        incident_supporting_evidence=incident_supporting_evidence,
        stale_or_historical_evidence=stale_or_historical_evidence,
        low_relevance_signals=low_relevance_signals,
    )
    if active_operational_brief:
        operational_assessment = build_operational_assessment_from_active_brief(
            active_operational_brief,
            fallback=operational_assessment,
        )

    return {
        "scope": "chat",
        "scope_context": {
            "host_id": host_id,
            "incident_id": incident_id,
            "hours": hours,
        },
        "question_kind": question_kind,
        "question_intent": question_intent,
        "response_contract": response_contract,
        "focus_resolution": focus_bundle.get("focus_resolution") or {},
        "focus_host": focus_host,
        "focus_incident": focus_incident,
        "active_incidents": focus_bundle.get("active_incidents") or [],
        "active_operational_brief": active_operational_brief,
        "recent_operational_signals": trim_ai_items(recent_operational_signals, 10),
        "incident_supporting_evidence": trim_ai_items(incident_supporting_evidence, 8),
        "stale_or_historical_evidence": trim_ai_items(stale_or_historical_evidence, 6),
        "low_relevance_signals": trim_ai_items(low_relevance_signals, 6),
        "operational_assessment": operational_assessment,
        "product_context": product_context,
        "environment_context": environment_context,
        "host_context": host_context,
        "incident_context": incident_context,
    }


def brief_signal_key(value: Optional[str]) -> str:
    normalized = normalize_incident_signal_name(value)
    category = incident_signal_category(normalized)
    if normalized == "BROADCAST_STORM":
        return "broadcast_storm"
    if normalized == "STP_DISABLED":
        return "stp_disabled"
    if normalized == "STP_TOPOLOGY_CHANGE":
        return "stp_topology_change"
    if normalized in {"MAC_FLAPPING", "MAC_FLAP", "MAC_MOVE"}:
        return "mac_flapping"
    if normalized in {"LINK_TRAP", "LINKUP", "LINKDOWN"}:
        return "link_up_down"
    if category == "loop_storm":
        return "loop_storm"
    if category == "mac_flap":
        return "mac_flapping"
    if category == "interface_flap":
        return "interface_flap"
    if category == "link_trap":
        return "link_up_down"
    return (normalized or "other").lower()


def brief_signal_priority(value: Optional[str]) -> int:
    key = brief_signal_key(value)
    return {
        "broadcast_storm": 7,
        "stp_disabled": 6,
        "stp_topology_change": 6,
        "loop_storm": 6,
        "mac_flapping": 5,
        "interface_flap": 4,
        "link_up_down": 3,
    }.get(key, 1)


def incident_freshness_rank(item: dict[str, Any]) -> int:
    timestamp = parse_ai_timestamp(item.get("last_seen_at") or item.get("opened_at"))
    if timestamp is None:
        return 0
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    age_hours = max(0.0, (datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds() / 3600)
    if age_hours <= 2:
        return 5
    if age_hours <= 12:
        return 4
    if age_hours <= 24:
        return 3
    if age_hours <= 72:
        return 2
    if age_hours <= 168:
        return 1
    return 0


def active_incident_focus_priority(item: dict[str, Any]) -> tuple[int, int, int, int, float, int]:
    signal_counts = item.get("signal_counts") if isinstance(item.get("signal_counts"), dict) else {}
    signal_contexts = list(item.get("signal_contexts") or [])
    evidences = list(item.get("evidences") or [])
    evidence_score = 0

    for signal, count in signal_counts.items():
        evidence_score += brief_signal_priority(signal) * max(1, min(int(count or 0), 6))

    for context_item in signal_contexts[:8]:
        evidence_score += brief_signal_priority(context_item.get("signal")) * max(1, min(int(context_item.get("count") or 0), 4))

    for raw_item in evidences[:8]:
        parsed = parse_incident_evidence_token(raw_item)
        if parsed:
            evidence_score += brief_signal_priority(parsed.get("signal"))

    return (
        1 if str(item.get("status") or "").strip().lower() == "open" else 0,
        incident_freshness_rank(item),
        severity_rank(item.get("severity")),
        evidence_score,
        ai_timestamp_epoch(item.get("last_seen_at") or item.get("opened_at")),
        int(item.get("id") or 0),
    )


def format_recent_evidence_item(item: dict[str, Any]) -> str:
    message = str(item.get("message") or "").strip()
    focus = str(
        item.get("interface_pair")
        or item.get("iface")
        or next(iter(item.get("interfaces") or []), "host")
    )
    if message:
        if focus not in {"", "host", "unknown"} and focus not in message:
            return f"{message} em {focus}."
        return message
    label = str(item.get("signal_label") or "Sinal")
    if focus not in {"", "host", "unknown"}:
        return f"{label} em {focus}."
    return label


def build_operational_commands(host: dict[str, Any], incident: dict[str, Any], assessment: dict[str, Any]) -> list[str]:
    incident_type = str(incident.get("incident_type") or "").strip().lower()
    host_template = str(host.get("template_slug") or host.get("template_name") or "").strip().lower()
    commands: list[str] = []

    if incident_type in {"host_down", "icmp_collection_silence"}:
        commands.extend([
            "ping <ip_do_host>",
            "traceroute <ip_do_host>",
            "show interface status",
            "show logging | include down|up|err-disable|link",
        ])
    if incident_type == "snmp_collection_silence":
        commands.extend([
            "snmpwalk -v2c -c <community> <ip_do_host> 1.3.6.1.2.1.1",
            "show snmp",
            "show logging | include SNMP|SNMPD|community",
        ])
    if incident_type == "loop_risk":
        commands.extend([
            "show spanning-tree detail",
            "show spanning-tree inconsistentports",
            "show interfaces counters errors",
            "show mac address-table dynamic",
            "show logging | include STP|LOOP|LOOPGUARD|MACFLAP|STORM|LINEPROTO",
        ])
    if incident_type in {"interface_down", "link_flap", "mac_flapping", "broadcast_storm"}:
        commands.extend([
            "show interfaces status",
            "show interfaces counters errors",
            "show logging | include LINK-3-UPDOWN|LINEPROTO|MACFLAP|STORM",
        ])
    if "linux" in host_template:
        commands.extend([
            "ping <ip_do_host>",
            "traceroute <ip_do_host>",
            "journalctl -n 100 --no-pager",
            "systemctl --failed",
            "ss -lntup",
        ])

    extra = list(assessment.get("runbooks") or [])
    for runbook in extra:
        for action in list(runbook.get("actions") or [])[:3]:
            action_text = str(action or "").strip()
            if action_text:
                commands.append(action_text)

    deduped = dedupe_text_items(commands)
    return deduped[:10]


def build_active_operational_brief(
    *,
    focus_host_context: Optional[dict[str, Any]] = None,
    focus_incident_context: Optional[dict[str, Any]] = None,
    focus_reason: str = "",
    recent_operational_signals: Optional[list[dict[str, Any]]] = None,
    incident_supporting_evidence: Optional[list[dict[str, Any]]] = None,
    stale_or_historical_evidence: Optional[list[dict[str, Any]]] = None,
    low_relevance_signals: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    host = (focus_host_context or {}).get("host") or (focus_incident_context or {}).get("host") or {}
    incident = (focus_incident_context or {}).get("incident") or {}
    recent_entries = list(recent_operational_signals or [])
    incident_entries = list(incident_supporting_evidence or [])
    historical_entries = list(stale_or_historical_evidence or [])
    low_entries = list(low_relevance_signals or [])
    recent_syslog = list((focus_host_context or {}).get("recent_syslog") or (focus_incident_context or {}).get("recent_syslog") or [])
    latest_metrics = list((focus_host_context or {}).get("latest_metrics") or (focus_incident_context or {}).get("latest_metrics") or [])
    recent_notifications = list((focus_host_context or {}).get("recent_notifications") or (focus_incident_context or {}).get("recent_notifications") or [])
    fallback_assessment = build_chat_operational_assessment_contextual(
        focus_host_context=focus_host_context,
        focus_incident_context=focus_incident_context,
        focus_reason=focus_reason,
        recent_operational_signals=recent_entries,
        incident_supporting_evidence=incident_entries,
        stale_or_historical_evidence=historical_entries,
        low_relevance_signals=low_entries,
    )
    if not host and not incident:
        return {}

    status_atual = humanize_health_status(host.get("health_status")) if host else "Desconhecido"
    posture = str(host.get("operational_posture") or "").strip()
    if posture:
        status_atual = f"{status_atual} | postura {posture}"
    if str(incident.get("incident_type") or "").strip().lower() == "loop_risk":
        status_atual = f"{status_atual} | risco de loop em observação"
    elif str(incident.get("incident_type") or "").strip().lower() == "snmp_collection_silence":
        status_atual = f"{status_atual} | sem telemetria SNMP recente"
    elif str(incident.get("incident_type") or "").strip().lower() == "icmp_collection_silence":
        status_atual = f"{status_atual} | sem telemetria ICMP recente"

    status_snmp = "Sem evidência suficiente"
    if any(str(item.get("metric") or "").startswith("snmp.") for item in latest_metrics):
        status_snmp = "SNMP ativo"
    elif any(str(item.get("incident_type") or "").strip().lower() == "snmp_collection_silence" for item in list((focus_host_context or {}).get("active_incidents") or (focus_incident_context or {}).get("active_incidents") or [])):
        status_snmp = "Sem telemetria SNMP recente"
    elif str(host.get("health_status") or "").strip().lower() in {"down", "critical"}:
        status_snmp = "Possivelmente indisponível"

    context_buckets: dict[str, dict[str, Any]] = {}

    def ensure_context_bucket(context_name: str) -> dict[str, Any]:
        bucket = context_buckets.get(context_name)
        if bucket is None:
            bucket = {
                "context": context_name,
                "signals": [],
                "recent_signals": [],
                "historical_signals": [],
                "last_seen_at": None,
            }
            context_buckets[context_name] = bucket
        return bucket

    def add_context_signal(context_name: Optional[str], signal_name: Optional[str], *, source: str, ts: Any = None) -> None:
        context_value = str(context_name or "").strip()
        if not context_value or context_value in {"host", "unknown"}:
            return
        signal_key = brief_signal_key(signal_name)
        bucket = ensure_context_bucket(context_value)
        if signal_key not in bucket["signals"]:
            bucket["signals"].append(signal_key)
        source_key = "recent_signals" if source == "recent" else "historical_signals"
        if signal_key not in bucket[source_key]:
            bucket[source_key].append(signal_key)
        if ts and (bucket.get("last_seen_at") is None or str(ts) > str(bucket.get("last_seen_at"))):
            bucket["last_seen_at"] = ts

    for item in recent_entries:
        context_name = (
            item.get("interface_pair")
            or item.get("focus")
            or next(iter(item.get("interfaces") or []), None)
        )
        add_context_signal(context_name, item.get("signal_type"), source="recent", ts=item.get("last_seen"))

    for item in incident_entries:
        add_context_signal(item.get("focus"), item.get("signal"), source="historical", ts=item.get("last_seen_at"))

    for item in list(incident.get("affected_contexts") or []):
        context_name = str(item or "").strip()
        if context_name and context_name not in context_buckets:
            ensure_context_bucket(context_name)

    affected_contexts = sorted(
        (
            {
                "context": bucket["context"],
                "signals": sorted(list(bucket["signals"]), key=brief_signal_priority, reverse=True),
                "recent_signals": sorted(list(bucket["recent_signals"]), key=brief_signal_priority, reverse=True),
                "historical_signals": sorted(list(bucket["historical_signals"]), key=brief_signal_priority, reverse=True),
                "last_seen_at": bucket.get("last_seen_at"),
            }
            for bucket in context_buckets.values()
        ),
        key=lambda item: (
            max((brief_signal_priority(signal) for signal in item.get("signals") or []), default=0),
            ai_timestamp_epoch(item.get("last_seen_at")),
            item.get("context") or "",
        ),
        reverse=True,
    )[:6]

    recent_evidence: list[str] = []
    for item in recent_syslog:
        signal_type = str(item.get("signal_type") or "")
        if signal_type == "other":
            continue
        summary = format_recent_evidence_item(item)
        if summary and summary not in recent_evidence:
            recent_evidence.append(summary)
        if len(recent_evidence) >= 6:
            break
    for item in recent_entries:
        summary = str(item.get("summary") or "").strip()
        if summary and summary not in recent_evidence:
            recent_evidence.append(summary)
        if len(recent_evidence) >= 6:
            break

    ordered_incident_entries = sorted(
        incident_entries,
        key=lambda item: (
            brief_signal_priority(item.get("signal")),
            1 if str(item.get("kind") or "") in {"signal_count", "signal_context", "evidence_item"} else 0,
            ai_timestamp_epoch(item.get("last_seen_at") or item.get("opened_at") or item.get("first_seen_at")),
        ),
        reverse=True,
    )
    historical_evidence: list[str] = []
    for item in ordered_incident_entries:
        summary = str(item.get("summary") or "").strip()
        if summary and summary not in historical_evidence:
            historical_evidence.append(summary)
        if len(historical_evidence) >= 6:
            break
    for item in historical_entries:
        if str(item.get("kind") or "") == "stale_notice":
            continue
        summary = str(item.get("summary") or "").strip()
        if summary and summary not in historical_evidence:
            historical_evidence.append(summary)
        if len(historical_evidence) >= 6:
            break

    lifecycle_status = "sem incidente aberto"
    if incident:
        if recent_evidence and historical_evidence:
            lifecycle_status = "incidente aberto com sinais recentes e evid?ncia hist?rica associada"
        elif recent_evidence:
            lifecycle_status = "incidente aberto com sinais recentes na janela atual"
        elif historical_evidence:
            lifecycle_status = "incidente aberto sustentado principalmente por evid?ncia hist?rica"
        else:
            lifecycle_status = "incidente aberto sem repeti??o clara dos mesmos sinais na janela atual"

    primary_problem = str(incident.get("incident_type") or "").strip() or "operacional"
    primary_problem_label = incident_type_label(primary_problem)
    severity = str(incident.get("severity") or host.get("max_incident_severity") or "").strip() or "unknown"
    host_name = str(host.get("name") or incident.get("hostname") or "host sem identifica??o")
    if incident:
        current_state = f"O principal problema atual est? em {host_name}, com incidente {primary_problem_label} de severidade {severity} ainda aberto."
    else:
        current_state = f"O principal problema atual est? em {host_name}."
    if recent_evidence and historical_evidence:
        current_state += " A janela recente ainda mostra sinais operacionais e o incidente segue sustentado por evid?ncia hist?rica."
    elif recent_evidence:
        current_state += " A janela recente ainda mostra sinais operacionais relevantes."
    elif historical_evidence:
        current_state += " A melhor evid?ncia dispon?vel neste momento ? hist?rica, ligada ao incidente que continua aberto."

    immediate_actions: list[str] = []
    for runbook in list(fallback_assessment.get("runbooks") or [])[:4]:
        for action in list(runbook.get("actions") or [])[:8]:
            action_text = str(action or "").strip()
            if action_text and action_text not in immediate_actions:
                immediate_actions.append(action_text)
            if len(immediate_actions) >= 8:
                break
        if len(immediate_actions) >= 8:
            break
    incident_type_norm = str(incident.get("incident_type") or "").strip().lower()
    if incident_type_norm == "snmp_collection_silence":
        immediate_actions = dedupe_text_items(
            [
                "Confirmar se SNMP est? habilitado no ativo e se a community/credencial configurada no NetGuard est? correta.",
                "Validar alcance UDP/161 entre o NetGuard e o host monitorado.",
                "Se o host foi cadastrado apenas para ICMP, ajustar o template/perfil para n?o exigir SNMP.",
                *immediate_actions,
            ]
        )
    elif incident_type_norm == "icmp_collection_silence":
        immediate_actions = dedupe_text_items(
            [
                "Confirmar se a coleta ICMP est? habilitada para este host.",
                "Validar alcance ICMP a partir do container/poller do NetGuard e de outro ponto da rede.",
                "Se ICMP estiver bloqueado por pol?tica, ajustar o perfil para evitar falso positivo.",
                *immediate_actions,
            ]
        )
    elif incident_type_norm == "host_down":
        immediate_actions = dedupe_text_items(
            [
                "Confirmar alcance ICMP a partir do NetGuard e de outro ponto da rede.",
                "Validar energia, uplink, VLAN de ger?ncia, gateway e ACL/firewall do ativo.",
                "Checar se SNMP e syslog ainda chegam no NetGuard.",
                *immediate_actions,
            ]
        )
    elif incident and incident.get("last_seen_at"):
        lifecycle_action = "Acompanhar se o last_seen_at do incidente para de atualizar ap?s a conten??o ou corre??o operacional."
        if lifecycle_action not in immediate_actions:
            immediate_actions.append(lifecycle_action)

    supporting_signals = dedupe_text_items(
        [
            *list(fallback_assessment.get("secondary_findings") or []),
            *list(fallback_assessment.get("supporting_signals") or []),
        ]
    )[:6]
    low_relevance = [str(item.get("summary") or "").strip() for item in low_entries if str(item.get("summary") or "").strip()][:6]
    confidence_basis = dedupe_text_items(
        [
            focus_reason,
            "A prioriza??o considerou severidade, rec?ncia e evid?ncia operacional concreta.",
            "Os sinais recentes da janela atual foram mantidos separados da evid?ncia hist?rica do incidente aberto.",
            "Sinais SNMP info e de baixo score ficaram separados como baixa relev?ncia operacional.",
        ]
    )[:4]

    operational_commands = build_operational_commands(host, incident, fallback_assessment)
    metric_evidence = [
        f"{item.get('metric')}={item.get('value')} {item.get('unit') or ''}".strip()
        for item in latest_metrics[:6]
        if item.get("metric") is not None and item.get("value") is not None
    ]
    icmp_metric_evidence = [
        f"{format_metric_name(item.get('metric'))}: {item.get('value')}{(' ' + str(item.get('unit'))) if item.get('unit') else ''}".strip()
        for item in latest_metrics
        if str(item.get("metric") or "").startswith("icmp.") or str(item.get("metric") or "") == "host.alive"
    ][:6]
    syslog_evidence = [
        str(item.get("message") or item.get("summary") or "").strip()
        for item in recent_syslog[:6]
        if str(item.get("message") or item.get("summary") or "").strip()
    ]
    interface_contexts = [
        str(item.get("context") or "").strip()
        for item in affected_contexts
        if str(item.get("context") or "").strip()
    ]
    recent_notifications = list((focus_host_context or {}).get("recent_notifications") or (focus_incident_context or {}).get("recent_notifications") or [])
    notification_evidence = [
        f"{str(item.get('channel') or '-')} | {str(item.get('provider') or '-')} | {str(item.get('delivery_status') or '-')} | {str(item.get('sent_at') or '-')}"
        for item in recent_notifications[:6]
    ]
    active_related_incidents = [
        {
            "id": item.get("id"),
            "title": item.get("title"),
            "incident_type": item.get("incident_type"),
            "severity": item.get("severity"),
            "status": item.get("status"),
            "opened_at": item.get("opened_at"),
            "last_seen_at": item.get("last_seen_at"),
        }
        for item in list((focus_host_context or {}).get("active_incidents") or (focus_incident_context or {}).get("active_incidents") or [])[:6]
    ]
    recent_related_incidents = [
        {
            "id": item.get("id"),
            "title": item.get("title"),
            "incident_type": item.get("incident_type"),
            "severity": item.get("severity"),
            "status": item.get("status"),
            "opened_at": item.get("opened_at"),
            "last_seen_at": item.get("last_seen_at"),
        }
        for item in list((focus_host_context or {}).get("recent_incidents") or (focus_incident_context or {}).get("recent_incidents") or [])[:6]
    ]
    recovery_details = dedupe_text_items(
        [
            str((incident.get("details") or {}).get("recovery_evidence") or "").strip(),
            str((incident.get("details") or {}).get("recovery_reason") or "").strip(),
            str((incident.get("details") or {}).get("resolution_reason") or "").strip(),
        ]
    )
    evidence_opening = dedupe_text_items(
        [
            str(incident.get("opening_reason") or "").strip(),
            *recent_evidence[:4],
            *[item.get("summary") for item in (incident_entries[:4] if incident_entries else []) if item.get("summary")],
        ]
    )
    evidence_recovery = recovery_details or [
        "Não há evidências de recuperação registradas no momento."
    ]
    snmp_status = "Sem evidência suficiente"
    if any(str(item.get("incident_type") or "").strip().lower() == "snmp_collection_silence" for item in active_related_incidents):
        snmp_status = "Sem telemetria SNMP recente"
    elif any(str(item.get("metric") or "").startswith("snmp.") for item in latest_metrics):
        snmp_status = "SNMP ativo"
    elif str(host.get("health_status") or "").strip().lower() in {"down", "critical"}:
        snmp_status = "Possivelmente indisponível"

    cause_candidates = dedupe_text_items(
        [
            *(fallback_assessment.get("inferences") or []),
            str(incident.get("opening_reason") or "").strip(),
            str(fallback_assessment.get("state") or "").strip(),
        ]
    )
    cause_probable = (
        cause_candidates[0]
        if cause_candidates
        else "Não há evidências suficientes para concluir a causa raiz."
    )
    if not evidence_opening and not evidence_recovery and not recent_evidence and not historical_evidence:
        cause_probable = "Não há evidências suficientes para concluir a causa raiz."

    current_health = humanize_health_status(host.get("health_status"))
    posture = str(host.get("operational_posture") or "").strip()
    status_atual = current_health
    if posture:
        status_atual = f"{current_health} | postura {posture}"
    if incident_type_norm == "loop_risk":
        status_atual = f"{current_health} | risco de loop em observação"
    elif incident_type_norm == "snmp_collection_silence":
        status_atual = f"{current_health} | sem telemetria SNMP recente"
    elif incident_type_norm == "icmp_collection_silence":
        status_atual = f"{current_health} | sem telemetria ICMP recente"

    return {
        "host_affectado": host.get("name"),
        "ip": host.get("ip") or incident.get("src_ip"),
        "status_atual": status_atual,
        "severidade": str(incident.get("severity") or host.get("max_incident_severity") or "unknown").strip(),
        "estado_atual": current_state,
        "status_snmp": snmp_status,
        "incidentes_abertos": active_related_incidents,
        "incidentes_recentes": recent_related_incidents,
        "metricas_icmp_recentes": icmp_metric_evidence,
        "metricas_recentes": metric_evidence[:6],
        "eventos_syslog_relevantes": syslog_evidence[:6],
        "interfaces_afetadas": interface_contexts[:6],
        "interfaces_envolvidas": interface_contexts[:6],
        "notificacoes_enviadas": notification_evidence,
        "evidencias_abertura": evidence_opening[:6],
        "evidencias_recuperacao": evidence_recovery[:4],
        "possivel_impacto": str(fallback_assessment.get("impact") or "").strip() or "Impacto nao definido no contexto atual.",
        "impacto_provavel": str(fallback_assessment.get("impact") or "").strip() or "Impacto nao definido no contexto atual.",
        "causa_provavel": cause_probable,
        "acoes_recomendadas": immediate_actions[:8],
        "comandos_validacao": operational_commands[:10],
        "limitacoes_analise": dedupe_text_items(
            [
                *list(fallback_assessment.get("limits") or []),
                "Sem topologia completa e sem valida??o direta do equipamento, a causa f?sica permanece hip?tese operacional.",
            ]
        )[:5],
        "limitacoes": dedupe_text_items(
            [
                *list(fallback_assessment.get("limits") or []),
                "Sem topologia completa e sem validação direta do equipamento, a causa física permanece hipótese operacional.",
            ]
        )[:5],
        "focused_incident": {
            "id": incident.get("id"),
            "title": incident.get("title"),
            "incident_type": incident.get("incident_type"),
            "severity": incident.get("severity"),
            "status": incident.get("status"),
            "opened_at": incident.get("opened_at"),
            "last_seen_at": incident.get("last_seen_at"),
        }
        if incident
        else None,
        "focus_reason": focus_reason,
        "affected_contexts": affected_contexts,
        "recent_evidence": recent_evidence[:6],
        "historical_evidence": historical_evidence[:6],
        "incident_lifecycle": {
            "status": incident.get("status"),
            "opened_at": incident.get("opened_at"),
            "last_seen_at": incident.get("last_seen_at"),
            "current_phase": lifecycle_status,
        }
        if incident
        else None,
        "context_summary": {
            "host": host.get("name"),
            "ip": host.get("ip") or incident.get("src_ip"),
            "severity": str(incident.get("severity") or host.get("max_incident_severity") or "unknown").strip(),
            "status": status_atual,
            "snmp_status": snmp_status,
        },
        "impact": str(fallback_assessment.get("impact") or "").strip(),
        "priority": str(fallback_assessment.get("priority") or "").strip(),
        "immediate_actions": immediate_actions[:8],
        "supporting_signals": supporting_signals,
        "low_relevance_signals": low_relevance,
        "limits": dedupe_text_items(
            [
                *list(fallback_assessment.get("limits") or []),
                *list(fallback_assessment.get("runbook_limits") or []),
            ]
        )[:5],
        "confidence_basis": confidence_basis,
        "technical_evidence": dedupe_text_items([*metric_evidence, *icmp_metric_evidence, *syslog_evidence, *recent_evidence, *historical_evidence])[:8],
        "operational_commands": operational_commands,
        "recent_notifications": notification_evidence[:6],
        "status_snmp": snmp_status,
    }


def build_operational_assessment_from_active_brief(
    brief: dict[str, Any],
    *,
    fallback: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if not brief:
        return dict(fallback or {})

    incident = brief.get("focus_incident") or {}
    facts = []
    status_atual = str(brief.get("status_atual") or brief.get("context_summary", {}).get("status") or "").strip()
    status_snmp = str(brief.get("status_snmp") or brief.get("context_summary", {}).get("snmp_status") or "").strip()
    if status_atual:
        facts.append(f"Status atual do host: {status_atual}.")
    if status_snmp:
        facts.append(f"Status SNMP: {status_snmp}.")
    if incident:
        incident_label = incident_type_label(incident.get("incident_type"), incident.get("title"))
        facts.append(
            f"Incidente principal do ambiente: {incident_label} (severidade {incident.get('severity') or '-'}) em {brief.get('host_affectado') or 'host sem identificação'}."
        )
    if brief.get("evidencias_abertura"):
        facts.extend(str(item) for item in list(brief.get("evidencias_abertura") or [])[:3] if str(item).strip())
    if brief.get("evidencias_recuperacao"):
        facts.extend(str(item) for item in list(brief.get("evidencias_recuperacao") or [])[:3] if str(item).strip())
    facts.extend(list(brief.get("recent_evidence") or [])[:3])
    for item in list(brief.get("affected_contexts") or [])[:3]:
        context_name = item.get("context") or "host"
        signals = ", ".join(str(signal) for signal in list(item.get("signals") or [])[:4])
        if signals:
            facts.append(f"{context_name}: {signals}.")

    return {
        **(fallback or {}),
        "state": brief.get("current_state") or (fallback or {}).get("state"),
        "impact": brief.get("impact") or (fallback or {}).get("impact"),
        "priority": brief.get("priority") or (fallback or {}).get("priority"),
        "facts": dedupe_text_items(facts)[:6],
        "secondary_findings": dedupe_text_items(list(brief.get("supporting_signals") or [])[:6]),
        "supporting_signals": dedupe_text_items(list(brief.get("historical_evidence") or [])[:6]),
        "inferences": dedupe_text_items(list((fallback or {}).get("inferences") or [])[:4]),
        "limits": dedupe_text_items(list(brief.get("limits") or [])[:5]),
        "runbooks": list((fallback or {}).get("runbooks") or [])[:4],
    }


def render_active_operational_brief_digest(brief: dict[str, Any]) -> str:
    if not brief:
        return ""

    lines = ["Operational brief:"]
    if brief.get("host_affectado"):
        lines.append(f"- Host afetado: {brief.get('host_affectado')}")
    if brief.get("ip"):
        lines.append(f"- IP: {brief.get('ip')}")
    if brief.get("estado_atual"):
        lines.append(f"- Estado atual: {brief.get('estado_atual')}")
    if brief.get("status_atual"):
        lines.append(f"- Status resumido: {brief.get('status_atual')}")
    if brief.get("status_snmp"):
        lines.append(f"- Status SNMP: {brief.get('status_snmp')}")
    if brief.get("severidade"):
        lines.append(f"- Severidade: {brief.get('severidade')}")

    focused_incident = brief.get("focused_incident") or {}
    if focused_incident:
        lines.append(
            f"- Incidente em foco: {focused_incident.get('title') or '-'} | tipo {focused_incident.get('incident_type') or '-'} | severidade {focused_incident.get('severity') or '-'} | status {focused_incident.get('status') or '-'}"
        )

    incidentes_abertos = list(brief.get("incidentes_abertos") or [])
    if incidentes_abertos:
        lines.append("- Incidentes abertos relacionados:")
        for item in incidentes_abertos[:4]:
            lines.append(
                f"  - {item.get('title') or item.get('incident_type') or '-'} | severidade {item.get('severity') or '-'} | status {item.get('status') or '-'}"
            )

    incidentes_recentes = list(brief.get("incidentes_recentes") or [])
    if incidentes_recentes:
        lines.append("- Incidentes recentes:")
        for item in incidentes_recentes[:4]:
            lines.append(
                f"  - {item.get('title') or item.get('incident_type') or '-'} | severidade {item.get('severity') or '-'} | status {item.get('status') or '-'}"
            )

    metricas_icmp = list(brief.get("metricas_icmp_recentes") or [])
    if metricas_icmp:
        lines.append("- Métricas ICMP recentes:")
        lines.extend(f"  - {item}" for item in metricas_icmp[:4])

    metricas_recentes = list(brief.get("metricas_recentes") or [])
    if metricas_recentes:
        lines.append("- Métricas recentes:")
        lines.extend(f"  - {item}" for item in metricas_recentes[:4])

    syslog_relevante = list(brief.get("eventos_syslog_relevantes") or [])
    if syslog_relevante:
        lines.append("- Syslog relevante:")
        lines.extend(f"  - {item}" for item in syslog_relevante[:4])

    interfaces = list(brief.get("interfaces_envolvidas") or [])
    if interfaces:
        lines.append("- Interfaces envolvidas:")
        lines.extend(f"  - {item}" for item in interfaces[:4])

    notificacoes = list(brief.get("notificacoes_enviadas") or [])
    if notificacoes:
        lines.append("- Notificações enviadas:")
        lines.extend(f"  - {item}" for item in notificacoes[:4])

    if brief.get("causa_provavel"):
        lines.append(f"- Causa provável: {brief.get('causa_provavel')}")
    if brief.get("impacto_provavel"):
        lines.append(f"- Impacto provável: {brief.get('impacto_provavel')}")

    opening = list(brief.get("evidencias_abertura") or [])
    if opening:
        lines.append("- Evidências de abertura:")
        lines.extend(f"  - {item}" for item in opening[:4])

    recovery = list(brief.get("evidencias_recuperacao") or [])
    if recovery:
        lines.append("- Evidências de recuperação:")
        lines.extend(f"  - {item}" for item in recovery[:4])

    actions = list(brief.get("acoes_recomendadas") or [])
    if actions:
        lines.append("- Ações recomendadas:")
        lines.extend(f"  - {item}" for item in actions[:6])

    commands = list(brief.get("comandos_validacao") or [])
    if commands:
        lines.append("- Comandos de validação:")
        lines.extend(f"  - `{item}`" for item in commands[:6])

    limits = list(brief.get("limitacoes") or [])
    if limits:
        lines.append("- Limitações da análise:")
        lines.extend(f"  - {item}" for item in limits[:5])

    return "\n".join(lines)



def build_chat_operational_assessment_contextual(
    *,
    focus_host_context: Optional[dict[str, Any]] = None,
    focus_incident_context: Optional[dict[str, Any]] = None,
    focus_reason: str = "",
    recent_operational_signals: Optional[list[dict[str, Any]]] = None,
    incident_supporting_evidence: Optional[list[dict[str, Any]]] = None,
    stale_or_historical_evidence: Optional[list[dict[str, Any]]] = None,
    low_relevance_signals: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    base = (
        (focus_host_context or {}).get("operational_assessment")
        or (focus_incident_context or {}).get("operational_assessment")
        or {}
    )
    host = (focus_host_context or {}).get("host") or (focus_incident_context or {}).get("host") or {}
    incident = (focus_incident_context or {}).get("incident") or {}
    recent_entries = list(recent_operational_signals or [])
    incident_entries = list(incident_supporting_evidence or [])
    historical_entries = list(stale_or_historical_evidence or [])
    low_entries = list(low_relevance_signals or [])

    facts: list[str] = []
    secondary_findings: list[str] = []
    supporting_signals: list[str] = []
    limits = list(base.get("limits") or [])
    inferences = list(base.get("inferences") or [])
    runbooks = list(base.get("runbooks") or [])
    state = str(base.get("state") or "Sem foco operacional definido.")
    impact = str(base.get("impact") or "Sem impacto operacional relevante definido.")
    priority = str(base.get("priority") or "monitorar")

    host_name = host.get("name")
    if host_name:
        state = f"O principal problema atual do ambiente esta em {host_name}. {state}"

    if incident:
        incident_type = incident.get("incident_type") or "operacional"
        severity = incident.get("severity") or "sem severidade"
        incident_title = incident.get("title") or "sem titulo"
        facts.append(
            f"Incidente principal do ambiente: {incident_title} ({incident_type_label(incident_type)}, severidade {severity}) em {host_name or 'host sem identificação'}."
        )

    strong_incident_evidence = any(
        incident_signal_category(item.get("signal")) in {"loop_storm", "mac_flap"}
        for item in incident_entries
        if str(item.get("kind") or "") in {"signal_count", "signal_context", "evidence_item"}
    )

    for item in recent_entries:
        summary = str(item.get("summary") or "").strip()
        if not summary:
            continue
        signal_type = str(item.get("signal_type") or "")
        if signal_type in {"loop_storm", "mac_flap"}:
            facts.append(summary)
        elif signal_type in {"interface_flap", "link_trap"}:
            secondary_findings.append(summary)
        else:
            supporting_signals.append(summary)

    for item in incident_entries:
        summary = str(item.get("summary") or "").strip()
        if not summary or summary in facts or summary in secondary_findings or summary in supporting_signals:
            continue
        kind = str(item.get("kind") or "")
        category = incident_signal_category(item.get("signal"))
        if kind in {"signal_count", "signal_context", "evidence_item"}:
            if category in {"loop_storm", "mac_flap"}:
                facts.append(summary)
            elif category in {"interface_flap", "link_trap"}:
                secondary_findings.append(summary)
            else:
                supporting_signals.append(summary)
            continue
        if kind == "opening_reason":
            if not strong_incident_evidence and len(facts) < 4:
                facts.append(summary)
            else:
                supporting_signals.append(summary)
            continue
        if kind == "affected_contexts":
            supporting_signals.append(summary)
            continue
        supporting_signals.append(summary)

    if focus_reason:
        focus_limit = f"Resolução de foco do chat: {focus_reason}"
        if focus_limit not in limits:
            limits.insert(0, focus_limit)

    if historical_entries:
        historical_limit = "Parte da explicação depende de evidência histórica do incidente aberto, separada dos sinais mais recentes do host."
        if historical_limit not in limits:
            limits.insert(0, historical_limit)
        historical_budget = 3
        for item in historical_entries:
            if historical_budget <= 0:
                break
            if str(item.get("kind") or "") == "stale_notice":
                continue
            summary = str(item.get("summary") or "").strip()
            if not summary or summary in facts or summary in secondary_findings or summary in supporting_signals:
                continue
            kind = str(item.get("kind") or "")
            category = incident_signal_category(item.get("signal"))
            if kind == "opening_reason" and strong_incident_evidence:
                continue
            if category in {"loop_storm", "mac_flap"} or kind in {"affected_contexts", "opening_reason"}:
                supporting_signals.append(summary)
                historical_budget -= 1

    for item in low_entries:
        summary = str(item.get("summary") or "").strip()
        if summary and summary not in supporting_signals and not facts and not secondary_findings:
            supporting_signals.append(summary)

    return {
        **base,
        "state": state,
        "impact": impact,
        "priority": priority,
        "facts": dedupe_text_items(facts)[:6],
        "secondary_findings": dedupe_text_items(secondary_findings)[:6],
        "supporting_signals": dedupe_text_items(supporting_signals)[:6],
        "inferences": dedupe_text_items(inferences)[:4],
        "limits": dedupe_text_items(limits)[:5],
        "runbooks": runbooks[:4],
    }


def build_ai_chat_prompt(message: str, context: dict[str, Any], history: list[dict[str, str]]) -> str:
    history_lines: list[str] = []
    for item in history[-3:]:
        role = "Usuário" if str(item.get("role") or "").strip().lower() == "user" else "Assistente"
        content = str(item.get("content") or "").strip()
        if not content:
            continue
        history_lines.append(f"{role}: {content}")

    history_block = "\n".join(history_lines) if history_lines else "Sem histórico anterior nesta sessão."
    context_block = build_prompt_context_digest(context, prompt_mode="chat")

    question_kind = str(context.get("question_kind") or "operational")
    normalized_message = normalize_chat_message(message)

    instructions = """
Tarefa: responder à pergunta do usuário com base no contexto disponível do NetGuard.
Regras:
- responda apenas no domínio do NetGuard;
- adapte o formato da resposta ao tipo de pergunta, sem repetir sempre a mesma estrutura;
- use prosa natural quando a pergunta for conceitual, estratégica, comparativa ou de produto;
- evite começar sempre com títulos, cabeçalhos ou blocos fixos;
- prefira texto corrido;
- use bullets apenas quando eles ajudarem de verdade e limite a lista ao essencial;
- por padrão, responda em 1 a 3 parágrafos curtos;
- se a pergunta for simples, responda de forma simples;
- evite textão, repetição e conclusões redundantes;
- prefira 2 ou 3 pontos fortes realmente relevantes em vez de repetir sempre a mesma lista de atributos;
- não use linguagem de sistema, de auditoria ou de bastidor de processamento;
- cite host, incidente, métricas, syslog, previsões, grupos, templates ou dashboards quando eles aparecerem no contexto;
- se não houver evidência suficiente, diga isso explicitamente;
- só sugira próximo passo manual quando a pergunta pedir ação, diagnóstico ou priorização;
- só destaque evidências explicitamente quando isso realmente ajudar a sustentar a resposta;
- não use "Próximo passo manual" nem "Evidências principais" por padrão;
- para perguntas estratégicas, responda com mais construção, contexto e posicionamento;
- feche a resposta de forma limpa, sem deixar frase em aberto;
- não proponha automação, remediação automática ou mudanças irreversíveis.
""".strip()

    if question_kind == "product":
        instructions += """

Regras adicionais para perguntas sobre o produto:
- priorize o contexto institucional e funcional do NetGuard;
- responda como alguém que conhece o produto e sabe explicá-lo com segurança;
- explique o que o produto faz hoje, o que coleta, onde ele já gera valor e como as áreas Monitoramento, Coleta de dados, Relatórios e IA / Insights se diferenciam;
- ancore a resposta no que já existe hoje: monitoramento por host, SNMP, syslog, incidentes, previsões, loop_risk, dashboards, grupos, templates e o fluxo do lab-linux-01 quando isso ajudar;
- use templates, dashboards, grupos, relatórios e IA apenas se eles existirem no contexto;
- não mande o usuário consultar documentação inexistente;
- diferencie claramente funcionalidades atuais de itens apenas planejados;
- trate o NetGuard como uma plataforma real em evolução, não como algo feito apenas para banca ou TCC;
- soe como alguém explicando uma solução de monitoramento com segurança, não como uma ficha técnica;
- evite adjetivos amplos como "completo", "enterprise" ou "altamente escalável" se isso não estiver claramente sustentado;
- escolha exemplos concretos do produto atual em vez de slogans repetidos.
""".strip()
    elif question_kind == "comparison":
        instructions += """

Regras adicionais para perguntas comparativas:
- responda com posicionamento claro, maduro e argumentativo, sem parecer marketing vazio;
- compare o NetGuard com plataformas como Zabbix e SolarWinds em termos de proposta de uso, não de benchmark inventado;
- explique onde o NetGuard é mais direto hoje: fluxo guiado por host, leitura operacional mais concentrada e menos dependência de navegação espalhada;
- destaque apenas os diferenciais que fizerem mais sentido para a pergunta, sem reciclar sempre a mesma lista;
- use exemplos concretos do produto atual, como host monitoring, incidentes, sinais recentes, loop_risk, dashboards por host e grupos/templates;
- admita limites atuais do projeto com segurança, sem enfraquecer a proposta;
- explique com clareza o que já entrega hoje, o que já gera valor agora e o que ainda é evolução;
- não prometa escala enterprise comprovada se isso não estiver no contexto;
- não fale como benchmark de mercado, fale como posicionamento de produto;
- deixe claro que o NetGuard não busca paridade total com suítes enterprise neste estágio, mas já tem proposta mais guiada e contextual no escopo que cobre hoje.
""".strip()
    elif question_kind == "presentation":
        instructions += """

Regras adicionais para perguntas de banca ou apresentação:
- responda como um especialista explicando o projeto com clareza e segurança;
- destaque o que é demonstrável hoje no ambiente real, especialmente com o lab-linux-01;
- organize a explicação de modo didático, mas sem cair em roteiro burocrático;
- se houver roadmap, separe claramente do que já está funcional.
""".strip()
    elif question_kind == "conceptual":
        instructions += """

Regras adicionais para perguntas conceituais:
- responda de forma direta, clara e natural, como alguém que conhece bem o produto;
- explique primeiro a ideia central e depois detalhe se isso ajudar;
- evite respostas excessivamente fragmentadas quando uma resposta corrida for melhor;
- não transforme toda explicação em checklist;
- dê exemplos concretos do produto quando isso deixar a resposta mais clara.
""".strip()
    else:
        instructions += """

Regras adicionais para perguntas operacionais:
- responda obrigatoriamente com as secoes: Fatos observados, Hipotese provavel, Impacto, O que fazer agora, Comandos de validacao e Limitacoes;
- priorize host, incidente, syslog, metricas, interfaces e dashboard em foco;
- se o host estiver saudavel, mantenha recomendacao conservadora e sem alarmismo;
- use evidencias e proximo passo s? quando isso ajudar a decisao operacional;
- nao alongue a resposta se a situacao ja estiver clara.
""".strip()


    if "zabbix" in normalized_message or "solarwinds" in normalized_message:
        instructions += "\n\n" + """

Ajuste adicional para esta pergunta:
- deixe a comparação mais concreta;
- explique que a diferença do NetGuard hoje está menos na amplitude de catálogo e mais no fluxo operacional orientado por host;
- mostre onde ele é mais guiado e direto sem sugerir que já substitui tudo o que uma suíte enterprise madura oferece.
""".strip()

    if "rede grande" in normalized_message or "escalavel" in normalized_message or "escalável" in normalized_message:
        instructions += "\n\n" + """

Ajuste adicional para esta pergunta:
- responda com honestidade sobre escala;
- explique o que já entrega valor hoje e por que grupos, templates e dashboards dão uma base consistente para evoluir;
- diga explicitamente que a expansão para cenários mais amplos ainda é evolução do produto, não capacidade já comprovada.
""".strip()

    return (
        f"{instructions}\n\n"
        f"Histórico recente da conversa:\n{history_block}\n\n"
        f"Pergunta atual:\n{message.strip()}\n\n"
        f"Contexto útil do NetGuard:\n{context_block}"
    )


def build_ai_prompt(insight_type: str, context: dict[str, Any]) -> str:
    context_block = build_prompt_context_digest(context, prompt_mode="insight")
    normalized = str(insight_type).strip().lower()

    if normalized == "host_summary":
        instructions = """
Tarefa: gerar um resumo operacional do host.
Formato esperado:
# Resumo do host
## Estado atual
- bullets curtos
## Sinais relevantes
- bullets curtos
## Observações
- bullets curtos
Regras:
- cite nome, IP, grupo, template, postura operacional e saúde quando existirem;
- use apenas incidentes, syslog, previsões e métricas presentes nas evidências;
- se houver sinais em interfaces diferentes, separe explicitamente cada contexto;
- não misture flap de interface com loop, storm ou MAC flap quando os sinais apontarem para interfaces ou pares distintos;
- cite a interface isolada e o par de interfaces explicitamente quando eles aparecerem nas evidências;
- trate traps linkUp/linkDown como apoio ao diagnóstico, sem transformá-los automaticamente em causa raiz;
- se não houver dados suficientes, diga isso explicitamente;
- não proponha automações nem ações irreversíveis;
- se o host estiver saudável e sem incidentes relevantes, mantenha tom conservador.
""".strip()
    elif normalized == "operational_recommendation":
        instructions = """
Tarefa: gerar uma recomendação operacional objetiva para o host.
Formato esperado:
# Recomendação operacional
## Prioridade imediata
- bullets curtos
## Próximos passos sugeridos
1. passos manuais e verificáveis
## Evidências consideradas
- bullets curtos
Regras:
- priorize ação operacional simples, manual e explicável;
- conecte a recomendação ao template do host quando isso fizer sentido;
- mantenha separados os achados por interface ou par de interfaces;
- se houver loop ou MAC flap em um par e flap em outra interface, priorize o loop, mas cite explicitamente o flap como evento distinto;
- use o agrupamento de sinais por interface/contexto para evitar conclusões genéricas;
- não invente comandos, configurações ou causas não suportadas;
- se o host estiver estável, recomende apenas acompanhamento e conferência de rotina;
- se houver atenção ou criticidade, seja proporcional ao nível de evidência.
""".strip()
    elif normalized == "incident_explanation":
        instructions = """
Tarefa: explicar tecnicamente o incidente para um operador.
Formato esperado:
# Explicação do incidente
## O que aconteceu
- bullets curtos
## Por que isso importa
- bullets curtos
## Evidências
- bullets curtos
## Ação sugerida
- bullets curtos
Regras:
- use tipo, severidade, status, host, grupo, recomendação atual e relação com loop_risk quando houver;
- deixe claro quando a correlação for parcial ou quando faltarem evidências;
- não extrapole além dos dados fornecidos;
- mantenha o texto técnico, curto e operacional.
""".strip()
    elif normalized == "technical_summary":
        instructions = """
Tarefa: gerar um resumo técnico formal, reutilizável em relatório ou TCC.
Formato esperado:
# Resumo técnico
## Contexto observado
parágrafo curto
## Achados principais
- bullets objetivos
## Interpretação técnica
parágrafo curto
## Conclusão
parágrafo curto
Regras:
- linguagem formal, objetiva e reaproveitável em texto acadêmico;
- ancore as afirmações nos dados reais do produto;
- cite o foco do laboratório quando ele estiver presente;
- não use tom promocional, genérico ou de chatbot.
""".strip()
    else:
        instructions = "Gere um insight técnico curto e estritamente ancorado nas evidências fornecidas."

    return f"{instructions}\n\nContexto estruturado do NetGuard:\n{context_block}"


def build_ai_chat_prompt(message: str, context: dict[str, Any], history: list[dict[str, str]]) -> str:
    history_lines: list[str] = []
    for item in history[-3:]:
        role = "Usuario" if str(item.get("role") or "").strip().lower() == "user" else "Assistente"
        content = str(item.get("content") or "").strip()
        if content:
            history_lines.append(f"{role}: {content}")

    history_block = "\n".join(history_lines) if history_lines else "Sem historico anterior nesta sessao."
    context_block = build_prompt_context_digest(context, prompt_mode="chat")
    question_kind = str(context.get("question_kind") or "operational")
    question_intent = str(context.get("question_intent") or ("status_atual" if question_kind == "operational" else question_kind))
    response_contract = context.get("response_contract") or build_response_contract_for_intent(question_intent)
    contract_block = render_response_contract_digest(response_contract)
    normalized_message = normalize_chat_message(message)

    instructions = """
Tarefa: responder a pergunta do usuario com base no contexto disponivel do NetGuard.
Regras:
- responda diretamente a pergunta, sem narrar JSON, secoes ou estrutura do contexto;
- responda apenas no dominio do NetGuard;
- use o contexto como base factual, nao como tema da resposta;
- para perguntas amplas sobre o ambiente, comece pelo foco operacional resolvido no contexto e nao por hosts estaveis sem incidente;
- diferencie explicitamente sinais recentes da janela atual, incidente ainda aberto e evidencias historicas que sustentaram a abertura;
- quando houver multiplos problemas simultaneos, liste todos os achados reais do periodo;
- use a severidade para priorizar a ordem, nunca para omitir um achado secundario real;
- diferencie problema principal, problemas adicionais e sinais de apoio quando isso ajudar;
- se houver loop_risk, broadcast storm, MAC flapping, STP desabilitado ou flap recorrente, trate isso como risco operacional relevante;
- nao minimize risco operacional relevante por causa de anomalias SNMP com severidade info;
- separe explicitamente fato observado, inferencia operacional e limite do que ainda nao da para afirmar quando isso fizer diferenca;
- cite host, incidente, metricas, syslog, previsoes, grupos, templates ou dashboards quando eles aparecerem no contexto;
- por padrao, responda em 1 a 3 paragrafos curtos;
- use bullets apenas quando eles ajudarem de verdade;
- evite repeticao, texto burocratico e frases em aberto;
- feche a resposta com uma conclusao completa;
- nao proponha automacao, remediacao automatica ou mudancas irreversiveis.
""".strip()

    if question_kind == "product":
        instructions += """

Regras adicionais para perguntas sobre o produto:
- explique o produto como alguem que conhece o NetGuard de fato;
- use exemplos concretos do que existe hoje no produto;
- diferencie claramente o que ja existe do que ainda e roadmap;
- nao mande consultar documentacao inexistente.
""".strip()
    elif question_kind == "comparison":
        instructions += """

Regras adicionais para perguntas comparativas:
- compare proposta de uso e experiencia operacional, nao benchmark inventado;
- destaque apenas os diferenciais que fizerem sentido para esta pergunta;
- admita limites atuais sem enfraquecer a proposta;
- nao prometa paridade enterprise onde ela nao existe.
""".strip()
    elif question_kind == "presentation":
        instructions += """

Regras adicionais para perguntas de apresentacao:
- explique de forma didatica, objetiva e segura;
- destaque o que e demonstravel hoje no ambiente real.
""".strip()
    elif question_kind == "conceptual":
        instructions += """

Regras adicionais para perguntas conceituais:
- explique primeiro a ideia central e depois detalhe se isso ajudar;
- evite transformar tudo em checklist.
""".strip()
    else:
        instructions += """

Regras adicionais para perguntas operacionais:
- priorize host, incidente, syslog, previsoes, metricas e dashboard em foco;
- se houver mais de um sinal ou problema no host, cite todos;
- separe problema principal, achados adicionais e sinais de apoio;
- se o host estiver saudavel, mantenha recomendacao conservadora e sem alarmismo;
- use runbooks operacionais do contexto quando eles existirem;
- sempre cubra estado atual, impacto provavel, prioridade, acao recomendada, evidencias e limites, ainda que em ordem adaptada a pergunta.
""".strip()

        if question_intent == "status_atual":
            instructions += "\n\nAjuste para esta intencao: use obrigatoriamente as secoes Fatos observados, Hipotese provavel, Impacto, O que fazer agora, Comandos de validacao e Limitacoes. Comece pelos fatos e mantenha o texto curto e tecnicamente ancorado."
        elif question_intent == "impacto":
            instructions += "\n\nAjuste para esta intencao: responda primeiro com o impacto e a prioridade, mas preserve as secoes Fatos observados, Hipotese provavel, O que fazer agora, Comandos de validacao e Limitacoes."
        elif question_intent == "acao_imediata":
            instructions += "\n\nAjuste para esta intencao: destaque O que fazer agora e Comandos de validacao, sem esconder os Fatos observados, a Hipotese provavel, o Impacto e as Limitacoes."
        elif question_intent == "causa_provavel":
            instructions += "\n\nAjuste para esta intencao: priorize a secao Hipotese provavel e explique claramente o limite da conclusao, mantendo o restante das secoes."
        elif question_intent == "evidencias":
            instructions += "\n\nAjuste para esta intencao: destaque a secao Fatos observados e as Evidencias usadas, mas nao omita Hipotese provavel, Impacto, O que fazer agora, Comandos de validacao e Limitacoes."


    if "zabbix" in normalized_message or "solarwinds" in normalized_message:
        instructions += "\n\nAjuste adicional: faca a comparacao de forma concreta e mostre onde o NetGuard e mais guiado e direto hoje."

    if "rede grande" in normalized_message or "escalavel" in normalized_message:
        instructions += "\n\nAjuste adicional: responda com honestidade sobre escala e deixe claro o que ja entrega valor hoje e o que ainda e evolucao."

    if contract_block:
        instructions += f"\n\n{contract_block}"

    return (
        f"{instructions}\n\n"
        f"Historico recente da conversa:\n{history_block}\n\n"
        f"Pergunta atual:\n{message.strip()}\n\n"
        f"Base factual para responder:\n{context_block}"
    )


def build_ai_prompt(insight_type: str, context: dict[str, Any]) -> str:
    context_block = build_prompt_context_digest(context, prompt_mode="insight")
    normalized = str(insight_type).strip().lower()

    if normalized == "host_summary":
        instructions = """
Tarefa: gerar um resumo operacional do host.
Formato esperado:
# Resumo do host
## Visao geral
- texto curto e direto
## Problemas identificados
- liste todos os achados reais, do principal aos secundarios
## Sinais de apoio
- bullets curtos
## Historico recente sem evidencia atual
- cite somente se existir historico no contexto
## Limites
- bullets curtos
## Recomendacoes
- bullets curtos
Regras:
- responda diretamente, sem comentar JSON, estrutura ou secoes do contexto;
- use apenas incidentes, syslog, previsoes e metricas presentes nas evidencias;
- liste todos os problemas detectados no periodo analisado;
- use "aberto" somente para incidentes com status open ou acknowledged;
- se o incidente estiver resolved ou closed, trate como historico recente, nao como problema atual;
- itens marcados como "Historico recente sem evidencia atual" nunca devem entrar em "Problemas identificados";
- nao classifique historico resolvido ou fora da janela curta como risco operacional atual;
- score 0% nao e anomalia operacional e nao deve aparecer como sinal de apoio;
- use a severidade apenas para priorizar a ordem dos achados;
- se houver loop_risk, storm, MAC flap ou flap recorrente somente no historico, trate como historico a acompanhar, nao como problema atual;
- nao minimize risco relevante por causa de anomalias SNMP info;
- se houver sinais em interfaces diferentes, separe explicitamente cada contexto;
- nao misture flap de interface com loop, storm ou MAC flap quando os sinais apontarem para interfaces ou pares distintos;
- cite a interface isolada e o par de interfaces explicitamente quando eles aparecerem nas evidencias;
- trate traps linkUp/linkDown como sinal de apoio, nao como causa raiz automatica;
- diferencie problema principal, problemas adicionais e sinais de apoio;
- separe fato observado, inferencia operacional e limite quando isso ficar implicito demais;
- se o host estiver saudavel e sem incidente relevante, mantenha tom conservador.
""".strip()
    elif normalized == "operational_recommendation":
        instructions = """
Tarefa: gerar uma recomendacao operacional objetiva para o host.
Formato esperado:
# Recomendacao operacional
## Prioridade imediata
- bullets curtos
## Demais achados relevantes
- bullets curtos
## Historico recente sem evidencia atual
- cite somente se existir historico no contexto
## Proximos passos sugeridos
1. passos manuais e verificaveis
## Sinais de apoio
- bullets curtos
## Limites
- bullets curtos
Regras:
- responda direto, sem comentar o formato do contexto recebido;
- liste todos os problemas reais relevantes antes dos proximos passos;
- use "aberto" somente para incidentes com status open ou acknowledged;
- se o incidente estiver resolved ou closed, trate como historico recente, nao como problema atual;
- itens marcados como "Historico recente sem evidencia atual" nunca devem entrar em "Prioridade imediata" nem "Demais achados relevantes";
- nao classifique historico resolvido ou fora da janela curta como risco operacional atual;
- score 0% nao e anomalia operacional e nao deve aparecer como sinal de apoio;
- mantenha separados os achados por interface ou par de interfaces;
- se houver loop ou MAC flap ativo em um par e flap ativo em outra interface, priorize o loop, mas cite explicitamente o flap como evento distinto;
- se houver runbooks operacionais no contexto, reutilize-os de forma curta e objetiva;
- use severidade para ordenar, nao para omitir;
- nao invente comandos, configuracoes ou causas nao suportadas;
- se o host estiver estavel, recomende apenas acompanhamento e conferencia de rotina.
""".strip()
    elif normalized == "incident_explanation":
        instructions = """
Tarefa: explicar tecnicamente o incidente para um operador.
Formato esperado:
# Explicacao do incidente
## Fatos observados
- bullets curtos
## Inferencia operacional
- bullets curtos
## Limites
- bullets curtos
## Acao recomendada
- bullets curtos
Regras:
- responda de forma curta, objetiva e operacional;
- use tipo, severidade, status, host, grupo e relacao com loop_risk quando houver;
- cite os contextos ou interfaces afetadas quando eles existirem;
- se houver mais de um problema correlato, cite todos e deixe claro qual e o principal;
- deixe claro quando a correlacao for parcial;
- nao minimize um incidente relevante por causa de anomalias de severidade baixa;
- nao extrapole alem das evidencias.
""".strip()
    elif normalized == "technical_summary":
        instructions = """
Tarefa: gerar um resumo tecnico formal, reaproveitavel em relatorio.
Regras:
- linguagem formal, objetiva e reaproveitavel;
- ancore as afirmacoes nos dados reais do produto;
- nao use tom promocional ou generico.
""".strip()
    else:
        instructions = "Gere um insight tecnico curto e estritamente ancorado nas evidencias fornecidas."

    return f"{instructions}\n\nBase factual do NetGuard:\n{context_block}"


def build_ai_chat_prompt(message: str, context: dict[str, Any], history: list[dict[str, str]]) -> str:
    history_lines: list[str] = []
    for item in history[-3:]:
        role = "Usuario" if str(item.get("role") or "").strip().lower() == "user" else "Assistente"
        content = str(item.get("content") or "").strip()
        if content:
            history_lines.append(f"{role}: {content}")

    history_block = "\n".join(history_lines) if history_lines else "Sem historico anterior nesta sessao."
    context_block = build_prompt_context_digest(context, prompt_mode="chat")
    question_kind = str(context.get("question_kind") or "operational")
    question_intent = str(context.get("question_intent") or ("status_atual" if question_kind == "operational" else question_kind))
    response_contract = context.get("response_contract") or build_response_contract_for_intent(question_intent)
    contract_block = render_response_contract_digest(response_contract)
    scope_context = context.get("scope_context") or {}
    explicit_host = scope_context.get("host_id") is not None
    explicit_incident = scope_context.get("incident_id") is not None
    normalized_message = normalize_chat_message(message)

    instructions = """
Tarefa: responder a pergunta do usuario com base no contexto disponivel do NetGuard.
Regras:
- responda diretamente a pergunta, sem narrar JSON, secoes ou estrutura do contexto;
- responda dentro do dominio do NetGuard, redes corporativas, monitoramento e artigo/TCC do projeto;
- use o contexto como base factual, nao como tema da resposta;
- para perguntas conceituais de redes ou artigo/TCC, use conhecimento tecnico geral e conecte com o NetGuard quando fizer sentido;
- para afirmar estado real do ambiente, use apenas evidencias do NetGuard;
- para perguntas operacionais, trate o active_operational_brief como a triagem NOC deterministica do maior risco ativo;
- use o active_operational_brief como fonte principal para foco, impacto, acoes e evidencias; use o restante do contexto apenas para complementar ou esclarecer;
- comece pelo principal problema operacional do contexto, nao por host saudavel ou resumo generico do ambiente;
- diferencie explicitamente sinais recentes da janela atual, incidente ainda aberto e evidencias historicas que sustentaram a abertura;
- quando houver multiplos problemas simultaneos, liste todos os achados reais do periodo;
- use a severidade para priorizar a ordem, nunca para omitir um achado secundario real;
- use primeiro evidencias concretas: host afetado, incidente principal, interfaces/contextos, sinais de syslog/correlacao e runbook aplicavel;
- nao use contadores do ambiente, limiares abstratos ou frases como "ha X incidentes abertos" como base principal da resposta;
- se houver loop_risk, broadcast storm, MAC flapping, STP desabilitado ou flap recorrente, trate isso como risco operacional relevante;
- nao minimize risco operacional relevante por causa de anomalias SNMP com severidade info;
- separe explicitamente fato observado, inferencia operacional e limite do que ainda nao da para afirmar quando isso fizer diferenca;
- cite host, incidente, metricas, syslog, previsoes, grupos, templates ou dashboards quando eles aparecerem no contexto;
- por padrao, responda em 1 a 3 paragrafos curtos;
- use bullets apenas quando eles ajudarem de verdade;
- evite repeticao, texto burocratico e frases em aberto;
- feche a resposta com uma conclusao completa;
- nao proponha automacao, remediacao automatica ou mudancas irreversiveis.
""".strip()

    if question_kind == "product":
        instructions += """

Regras adicionais para perguntas sobre o produto:
- explique o produto como alguem que conhece o NetGuard de fato;
- use exemplos concretos do que existe hoje no produto;
- diferencie claramente o que ja existe do que ainda e roadmap;
- nao mande consultar documentacao inexistente.
""".strip()
    elif question_kind == "comparison":
        instructions += """

Regras adicionais para perguntas comparativas:
- compare proposta de uso e experiencia operacional, nao benchmark inventado;
- destaque apenas os diferenciais que fizerem sentido para esta pergunta;
- admita limites atuais sem enfraquecer a proposta;
- nao prometa paridade enterprise onde ela nao existe.
""".strip()
    elif question_kind == "presentation":
        instructions += """

Regras adicionais para perguntas de apresentacao:
- explique de forma didatica, objetiva e segura;
- destaque o que e demonstravel hoje no ambiente real.
""".strip()
    elif question_kind == "article":
        instructions += """

Regras adicionais para perguntas sobre artigo/TCC:
- responda como apoio tecnico ao artigo do NetGuard;
- explique metricas, metodologia, resultados e comparacoes de forma defensavel para banca;
- para MTTR, MTTD, MTTA, MTBF, SLA ou disponibilidade, de formula, fonte de dado esperada e ressalva quando nao houver amostra historica suficiente;
- compare com Zabbix/SolarWinds apenas como benchmark conceitual e funcional, sem prometer paridade total ou desempenho superior sem experimento controlado;
- diferencie claramente dado medido, inferencia tecnica e roadmap.
""".strip()
    elif question_kind == "network":
        instructions += """

Regras adicionais para perguntas de redes:
- responda como especialista de redes corporativas, nao apenas como leitor de incidentes;
- explique conceitos de ICMP, TCP/UDP, SNMP, syslog, VLAN, STP/RSTP, Loop Guard, CIDR, gateway, DNS, DHCP, latencia, perda, jitter e troubleshooting quando perguntado;
- conecte a explicacao com o NetGuard quando isso ajudar, mas nao force um incidente atual se a pergunta for conceitual;
- para estado real do ambiente, separe teoria de rede das evidencias coletadas pelo NetGuard;
- se a resposta depender de topologia, configuracao ou captura que nao esteja no contexto, diga isso claramente.
""".strip()
    elif question_kind == "conceptual":
        instructions += """

Regras adicionais para perguntas conceituais:
- explique primeiro a ideia central e depois detalhe se isso ajudar;
- evite transformar tudo em checklist.
""".strip()
    else:
        instructions += """

Regras adicionais para perguntas operacionais:
- responda nesta ordem sempre que fizer sentido: problema principal, impacto provavel, prioridade, acao imediata, evidencias concretas, limites/incertezas;
- comece pelo foco do active_operational_brief, nunca por host saudavel se houver incidente critico ou high aberto;
- priorize host, incidente, syslog, previsoes, metricas e dashboard em foco;
- use o runbook operacional do problema principal como base da acao recomendada;
- se houver mais de um sinal ou problema no host, cite todos;
- separe problema principal, achados adicionais e sinais de apoio;
- trate anomalias SNMP info e de baixo score apenas como apoio de baixa relevancia.
""".strip()

        if not explicit_host and not explicit_incident:
            instructions += """

Ajuste adicional para perguntas operacionais no escopo geral do ambiente:
- trate o foco operacional resolvido no contexto como o principal problema atual do ambiente;
- use o active_operational_brief como base principal da resposta;
- se existir incidente aberto em um host, responda primeiro sobre ele e so depois, se necessario, mencione outros hosts saudaveis;
- nao comece por hosts estaveis como lab-linux-01 se houver incidente ativo mais grave em outro host;
- para o problema principal, use nome do host, incidente, interfaces/contextos, sinais concretos e runbook operacional;
- nao use contadores de ambiente, numero de incidentes abertos ou limiares abstratos como evidencia principal.
""".strip()

        if question_intent == "status_atual":
            instructions += """

Ajuste para esta intencao:
- abra com o principal problema atual do ambiente ou do host em foco;
- use primeiro o host em foco, o incidente principal e os contextos afetados do active_operational_brief;
- se houver flap/trap em outra interface, cite isso como problema adicional, sem misturar com o loop principal.
""".strip()
        elif question_intent == "impacto":
            instructions += """

Ajuste para esta intencao:
- diga primeiro se o risco e grave para o segmento afetado;
- se houver loop_risk, storm ou MAC flapping, trate como risco de degradacao severa ou indisponibilidade do segmento L2 afetado;
- nao afirme queda da rede inteira sem topologia completa;
- nao minimize o risco por causa de SNMP info.
""".strip()
        elif question_intent == "acao_imediata":
            instructions += """

Ajuste para esta intencao:
- comece pelo runbook concreto do incidente principal;
- para loop_risk, priorize: isolar uma das portas envolvidas, validar STP/RSTP, validar Loop Guard, verificar redundância indevida ou cabo em loop, confirmar se storm e MAC flapping cessaram;
- não responda com "realizar análise detalhada" como ação principal;
- trate flap/trap de outra interface como trabalho separado, não como ação principal do loop.
""".strip()
        elif question_intent == "evidencias":
            instructions += """

Ajuste para esta intencao:
- cite primeiro as evidências concretas do host em foco;
- priorize mensagens, contextos afetados e sinais concretos do active_operational_brief;
- diferencie claramente sinal recente, incidente ainda aberto e evidência histórica que sustentou a abertura;
- não use totais do ambiente como evidência principal.
""".strip()

    if "zabbix" in normalized_message or "solarwinds" in normalized_message:
        instructions += "\n\nAjuste adicional: faça a comparação de forma concreta e mostre onde o NetGuard é mais guiado e direto hoje."

    if "rede grande" in normalized_message or "escalavel" in normalized_message or "escalavel" in normalized_message:
        instructions += "\n\nAjuste adicional: responda com honestidade sobre escala e deixe claro o que já entrega valor hoje e o que ainda é evolução."

    if contract_block:
        instructions += f"\n\n{contract_block}"

    return (
        f"{instructions}\n\n"
        f"Histórico recente da conversa:\n{history_block}\n\n"
        f"Pergunta atual:\n{message.strip()}\n\n"
        f"Base factual para responder:\n{context_block}"
    )


def ai_num_predict_for_insight(insight_type: str) -> int:
    normalized = str(insight_type or "").strip().lower()
    values = {
        "host_summary": 360,
        "operational_recommendation": 360,
        "incident_explanation": 340,
        "technical_summary": 420,
    }
    return values.get(normalized, 420)


def markdown_bullets(items: list[Any], empty: str) -> str:
    lines: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text:
            lines.append(f"- {text}")
    return "\n".join(lines) if lines else f"- {empty}"


def markdown_numbered(items: list[Any], empty: str) -> str:
    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        text = str(item or "").strip()
        if text:
            lines.append(f"{index}. {text}")
    return "\n".join(lines) if lines else f"1. {empty}"


def collect_runbook_actions(runbooks: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    for runbook in runbooks:
        title = str(runbook.get("title") or "").strip()
        for action in list(runbook.get("actions") or [])[:3]:
            action_text = str(action or "").strip()
            if action_text:
                actions.append(f"{title}: {action_text}" if title else action_text)
    return dedupe_text_items(actions)[:6]


def build_fallback_host_summary(context: dict[str, Any], reason: str) -> str:
    host = context.get("host") or {}
    assessment = build_host_operational_assessment(context)
    facts = list(assessment.get("facts") or [])
    secondary = list(assessment.get("secondary_findings") or [])
    supporting = list(assessment.get("supporting_signals") or [])
    limits = list(assessment.get("limits") or [])
    actions = collect_runbook_actions(list(assessment.get("runbooks") or []))
    overview = [
        f"Host: {host.get('name') or 'sem nome'} ({host.get('ip') or 'sem IP'}).",
        f"Grupo: {host.get('group_path') or host.get('group_name') or 'sem grupo'}; template: {host.get('template_name') or 'sem template'}.",
        f"Saúde: {host.get('health_status') or '-'}; postura: {host.get('operational_posture') or '-'}.",
        str(assessment.get("state") or "").strip(),
    ]

    return "\n\n".join(
        [
            "# Resumo do host",
            "## Visão geral\n" + markdown_bullets(overview, "Sem contexto suficiente do host."),
            "## Problemas identificados\n"
            + markdown_bullets(
                dedupe_text_items([*facts, *secondary]),
                "Nenhum problema relevante foi identificado no período analisado.",
            ),
            "## Sinais de apoio\n" + markdown_bullets(supporting, "Sem sinais de apoio adicionais no recorte atual."),
            "## Limites\n"
            + markdown_bullets(
                [
                    *limits,
                    "O modelo local Ollama não respondeu; este insight foi gerado pelo motor determinístico do NetGuard.",
                ],
                "Sem limitações adicionais registradas.",
            ),
            "## Recomendações\n"
            + markdown_bullets(actions, "Manter acompanhamento operacional e repetir a coleta se surgirem novos sinais."),
        ]
    )


def build_fallback_operational_recommendation(context: dict[str, Any], reason: str) -> str:
    assessment = build_host_operational_assessment(context)
    actions = collect_runbook_actions(list(assessment.get("runbooks") or []))
    findings = dedupe_text_items(
        [
            *list(assessment.get("facts") or []),
            *list(assessment.get("secondary_findings") or []),
        ]
    )

    return "\n\n".join(
        [
            "# Recomendação operacional",
            "## Prioridade imediata\n"
            + markdown_bullets(
                [
                    f"Prioridade: {assessment.get('priority') or 'acompanhar'}.",
                    str(assessment.get("state") or "").strip(),
                    str(assessment.get("impact") or "").strip(),
                ],
                "Sem prioridade operacional elevada no recorte atual.",
            ),
            "## Demais achados relevantes\n"
            + markdown_bullets(findings, "Nenhum achado adicional relevante foi identificado."),
            "## Próximos passos sugeridos\n"
            + markdown_numbered(
                actions,
                "Acompanhar a telemetria do host e validar manualmente se novos incidentes aparecerem.",
            ),
            "## Sinais de apoio\n"
            + markdown_bullets(list(assessment.get("supporting_signals") or []), "Sem sinais de apoio adicionais."),
            "## Limites\n"
            + markdown_bullets(
                [
                    *list(assessment.get("limits") or []),
                    "O modelo local Ollama está indisponível no endpoint configurado; a recomendação acima usa apenas regras e contexto estruturado do NetGuard.",
                ],
                "Sem limitações adicionais registradas.",
            ),
        ]
    )


def build_fallback_incident_explanation(context: dict[str, Any], reason: str) -> str:
    assessment = build_incident_operational_assessment(context)
    incident = context.get("incident") or {}
    host = context.get("host") or {}

    return "\n\n".join(
        [
            "# Explicação do incidente",
            "## Fatos observados\n"
            + markdown_bullets(
                [
                    f"Incidente #{incident.get('id') or '-'}: {incident.get('title') or incident.get('incident_type') or 'sem título'}.",
                    f"Host: {host.get('name') or '-'} ({host.get('ip') or '-'}).",
                    f"Severidade: {incident.get('severity') or '-'}; status: {incident.get('status') or '-'}.",
                    *list(assessment.get("facts") or []),
                ],
                "Sem fatos estruturados suficientes para explicar o incidente.",
            ),
            "## Inferencia operacional\n"
            + markdown_bullets(
                list(assessment.get("inferences") or []),
                str(assessment.get("state") or "Correlação parcial no recorte atual."),
            ),
            "## Limites\n"
            + markdown_bullets(
                [
                    *list(assessment.get("limits") or []),
                    "O modelo local Ollama não respondeu; esta explicação foi gerada pelo motor determinístico do NetGuard.",
                ],
                "Sem limitações adicionais registradas.",
            ),
            "## Ação recomendada\n"
            + markdown_bullets(
                collect_runbook_actions(list(assessment.get("runbooks") or [])),
                "Validar o host e os eventos relacionados antes de executar qualquer mudança operacional.",
            ),
        ]
    )


def build_fallback_technical_summary(context: dict[str, Any], reason: str) -> str:
    focus = context.get("focus") or context.get("scope") or "ambiente NetGuard"
    hosts = list(context.get("hosts") or context.get("host_samples") or [])
    incidents = list(context.get("incidents") or context.get("recent_incidents") or [])
    events = list(context.get("events") or context.get("recent_events") or [])
    findings: list[str] = []
    if hosts:
        findings.append(f"Foram considerados {len(hosts)} host(s) no contexto técnico.")
    if incidents:
        findings.append(f"O contexto inclui {len(incidents)} incidente(s) ou ocorrência(s) operacional(is).")
    if events:
        findings.append(f"O relatório considera {len(events)} evento(s) consolidado(s).")
    if not findings:
        findings.append("O contexto estruturado está disponível, mas sem amostra ampla suficiente para conclusões quantitativas.")

    return "\n\n".join(
        [
            "# Resumo técnico",
            "## Contexto observado\n"
            f"O recorte analisado corresponde a {focus}. A síntese abaixo foi gerada com base no contexto estruturado do NetGuard.",
            "## Achados principais\n" + markdown_bullets(findings, "Sem achados principais suficientes."),
            "## Interpretação técnica\n"
            "O NetGuard consegue consolidar hosts, incidentes, sinais e evidências para apoiar rastreabilidade operacional. "
            "Quando faltam dados históricos ou topologia completa, a interpretação deve ser tratada como parcial.",
            "## Conclusão\n"
            "O modelo local Ollama não respondeu no endpoint configurado; por isso este texto foi gerado pelo fallback determinístico, "
            "sem inventar métricas ou prometer comparações não medidas.",
        ]
    )


def build_fallback_ai_insight_content(insight_type: str, context: dict[str, Any], reason: str) -> str:
    normalized = str(insight_type or "").strip().lower()
    if normalized == "host_summary":
        return build_fallback_host_summary(context, reason)
    if normalized == "operational_recommendation":
        return build_fallback_operational_recommendation(context, reason)
    if normalized == "incident_explanation":
        return build_fallback_incident_explanation(context, reason)
    if normalized == "technical_summary":
        return build_fallback_technical_summary(context, reason)
    return "\n\n".join(
        [
            "# Insight técnico",
            "O modelo local Ollama não respondeu no endpoint configurado.",
            "O NetGuard manteve a resposta limitada ao contexto estruturado disponível, sem gerar conclusões externas.",
        ]
    )


def generate_ai_insight(
    cur,
    *,
    target_type: str,
    target_id: int,
    insight_type: str,
    context: dict[str, Any],
    refresh: bool = False,
) -> dict[str, Any]:
    if not has_ai_insights_schema(cur):
        raise HTTPException(
            status_code=503,
            detail="A tabela de ai_insights ainda não foi inicializada no banco.",
        )

    normalized_target_type = str(target_type).strip().lower()
    normalized_insight_type = str(insight_type).strip().lower()
    normalized_target_id = int(target_id or 0)

    if not refresh:
        cached = get_cached_ai_insight_record(
            cur,
            target_type=normalized_target_type,
            target_id=normalized_target_id,
            insight_type=normalized_insight_type,
        )
        if cached is not None:
            cached["cached"] = True
            return cached

    prompt = build_ai_prompt(normalized_insight_type, context)

    fallback_reason = None
    try:
        result = generate_ai_text(
            system=AI_SYSTEM_PROMPT,
            prompt=prompt,
            temperature=0.1,
            num_predict=ai_num_predict_for_insight(normalized_insight_type),
        )
    except OllamaClientError as exc:
        fallback_reason = str(exc)
        result = OllamaGenerateResult(
            model="NetGuard fallback",
            response=build_fallback_ai_insight_content(normalized_insight_type, context, fallback_reason),
            raw={
                "fallback": "ollama_unavailable",
                "ollama_error": fallback_reason,
            },
        )

    expires_at = datetime.now(timezone.utc) + timedelta(hours=ai_insight_ttl_hours(normalized_insight_type))
    evidence_json = dict(context or {})
    evidence_json["context_version"] = AI_CONTEXT_VERSION
    stored = store_ai_insight_record(
        cur,
        target_type=normalized_target_type,
        target_id=normalized_target_id,
        insight_type=normalized_insight_type,
        model=result.model,
        content_md=result.response,
        content_json={
            "format": "markdown",
            "prompt_category": normalized_insight_type,
            "target_type": normalized_target_type,
            "target_id": normalized_target_id,
            **({"fallback": "ollama_unavailable", "ollama_error": fallback_reason} if fallback_reason else {}),
        },
        evidence_json=evidence_json,
        expires_at=expires_at,
    )
    stored["cached"] = False
    return stored


@app.get("/signals/recent", response_model=List[RecentSignalOut])
def list_recent_signals(
    asset_id: Optional[int] = None,
    host_id: Optional[int] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    source: Optional[str] = None,
    signal_type: Optional[str] = Query(None, alias="type"),
    severity: Optional[str] = None,
    q: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 120,
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)
    normalized_asset_id = asset_id if asset_id is not None else host_id
    normalized_source = normalize_status_value(source)
    normalized_type = normalize_status_value(signal_type)
    normalized_severity = normalize_severity_value(severity)
    fetch_limit = max(normalize_limit(limit, default=120, maximum=1000), 20) * 2

    with get_conn() as conn, conn.cursor() as cur:
        records: list[dict[str, Any]] = []

        if normalized_source in (None, "all", "syslog"):
            syslog_records = select_syslog_records(
                cur,
                asset_id=normalized_asset_id,
                group_id=group_id,
                template_id=template_id,
                severity=normalized_severity,
                q=q,
                from_ts=parsed_from,
                to_ts=parsed_to,
                limit=fetch_limit,
            )
            for item in syslog_records:
                records.append(
                    {
                        "id": f"syslog-{item['id']}",
                        "ts": item["ts"],
                        "source": "syslog",
                        "signal_type": normalize_status_value(item.get("subsystem")) or "syslog",
                        "title": item["message"],
                        "message": item.get("raw") or item["message"],
                        "hostname": item["hostname"],
                        "src_ip": item["src_ip"],
                        "asset_id": item["asset_id"],
                        "group_id": item["group_id"],
                        "group_name": item["group_name"],
                        "group_path": item["group_path"],
                        "template_id": item["template_id"],
                        "template_name": item["template_name"],
                        "severity": item.get("severity"),
                        "status": None,
                        "subsystem": item.get("subsystem"),
                        "iface": item.get("iface"),
                        "details": {"event_id": item.get("event_id"), "process": item.get("process")},
                    }
                )

        if normalized_source in (None, "all", "incident"):
            incident_records = select_incident_records(
                cur,
                asset_id=normalized_asset_id,
                group_id=group_id,
                template_id=template_id,
                severity=normalized_severity,
                q=q,
                from_ts=parsed_from,
                to_ts=parsed_to,
                limit=fetch_limit,
            )
            for item in incident_records:
                records.append(
                    {
                        "id": f"incident-{item['id']}",
                        "ts": item["last_seen_at"] or item["opened_at"],
                        "source": "incident",
                        "signal_type": normalize_status_value(item["incident_type"]) or "incident",
                        "title": item["title"],
                        "message": item["details"].get("recommendation") or item["title"],
                        "hostname": item["hostname"],
                        "src_ip": item["src_ip"],
                        "asset_id": item["asset_id"],
                        "group_id": item["group_id"],
                        "group_name": item["group_name"],
                        "group_path": item["group_path"],
                        "template_id": item["template_id"],
                        "template_name": item["template_name"],
                        "severity": item["severity"],
                        "status": item["status"],
                        "subsystem": None,
                        "iface": item["details"].get("ifName"),
                        "details": item["details"],
                    }
                )

        if normalized_source in (None, "all", "prediction"):
            prediction_records = select_prediction_records(
                cur,
                asset_id=normalized_asset_id,
                group_id=group_id,
                template_id=template_id,
                q=q,
                from_ts=parsed_from,
                to_ts=parsed_to,
                limit=fetch_limit,
            )
            for item in prediction_records:
                iface = item["details"].get("ifName")
                if not iface and "=" in str(item["key"]):
                    iface = str(item["key"]).split("=", 1)[1]

                records.append(
                    {
                        "id": f"prediction-{item['asset_id']}-{item['metric']}-{item['ts']}",
                        "ts": item["ts"],
                        "source": "prediction",
                        "signal_type": normalize_status_value(item["metric"]) or "prediction",
                        "title": item["metric"],
                        "message": item["details"].get("recommendation")
                        or f"Score {int(round(item['score'] * 100))}% para {item['metric']}",
                        "hostname": item["hostname"],
                        "src_ip": item["src_ip"],
                        "asset_id": item["asset_id"],
                        "group_id": item["group_id"],
                        "group_name": item["group_name"],
                        "group_path": item["group_path"],
                        "template_id": item["template_id"],
                        "template_name": item["template_name"],
                        "severity": item["severity"],
                        "status": None,
                        "subsystem": item["details"].get("source"),
                        "iface": iface,
                        "details": item["details"],
                    }
                )

    filtered_records = []
    for item in records:
        if normalized_type and item["signal_type"] != normalized_type:
            continue
        if normalized_severity and normalize_severity_value(item.get("severity")) != normalized_severity:
            continue
        filtered_records.append(item)

    filtered_records.sort(key=lambda item: item["ts"], reverse=True)
    limited_records = filtered_records[: normalize_limit(limit, default=120, maximum=1000)]
    return [RecentSignalOut(**item) for item in limited_records]


@app.get("/reports/events", response_model=List[ReportEventOut])
def list_report_events(
    asset_id: Optional[int] = None,
    host_id: Optional[int] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 500,
):
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)
    normalized_asset_id = asset_id if asset_id is not None else host_id

    with get_conn() as conn, conn.cursor() as cur:
        records = build_report_event_records(
            cur,
            asset_id=normalized_asset_id,
            group_id=group_id,
            template_id=template_id,
            source=source,
            severity=severity,
            q=q,
            from_ts=parsed_from,
            to_ts=parsed_to,
            limit=limit,
        )

    return [ReportEventOut(**item) for item in records]


@app.get("/reports/availability")
def get_availability_report(
    asset_id: Optional[int] = None,
    host_id: Optional[int] = None,
    days: int = 7,
    min_samples: int = 1,
    limit: int = 500,
):
    normalized_asset_id = asset_id if asset_id is not None else host_id
    window_days = max(1, min(int(days or 7), 365))
    sample_floor = max(1, int(min_samples or 1))
    row_limit = normalize_limit(limit, default=500, maximum=2000)

    conditions = ["a.enabled = true"]
    params: list[Any] = [window_days]
    if normalized_asset_id is not None:
        conditions.append("a.id = %s")
        params.append(normalized_asset_id)

    where_clause = " AND ".join(conditions)
    params.extend([sample_floor, row_limit])

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT
                a.id,
                a.name,
                split_part(a.ip::text, '/', 1) AS ip,
                COUNT(m.value) AS samples,
                AVG(CASE WHEN m.value >= 1 THEN 1.0 ELSE 0.0 END) * 100.0 AS availability_pct,
                MIN(m.ts) AS first_sample_at,
                MAX(m.ts) AS last_sample_at
            FROM {ASSETS_TABLE} a
            LEFT JOIN metrics m
              ON m.asset_id = a.id
             AND m.metric = 'host.alive'
             AND m.ts >= now() - (%s::int * interval '1 day')
            WHERE {where_clause}
            GROUP BY a.id, a.name, a.ip
            HAVING COUNT(m.value) >= %s
            ORDER BY availability_pct ASC NULLS LAST, a.name ASC
            LIMIT %s
            """,
            params,
        )
        rows = cur.fetchall()

    return {
        "window_days": window_days,
        "min_samples": sample_floor,
        "items": [
            {
                "asset_id": row[0],
                "name": row[1],
                "ip": row[2],
                "samples": int(row[3] or 0),
                "availability_pct": round(float(row[4]), 2) if row[4] is not None else None,
                "first_sample_at": to_iso(row[5]),
                "last_sample_at": to_iso(row[6]),
            }
            for row in rows
        ],
    }


@app.get("/reports/incidents")
def get_incidents_report(
    asset_id: Optional[int] = None,
    host_id: Optional[int] = None,
    group_id: Optional[int] = None,
    template_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 200,
):
    normalized_asset_id = asset_id if asset_id is not None else host_id
    normalized_limit = normalize_limit(limit, default=200, maximum=2000)

    with get_conn() as conn, conn.cursor() as cur:
        records = select_incident_records(
            cur,
            asset_id=normalized_asset_id,
            group_id=group_id,
            template_id=template_id,
            severity=normalize_severity_value(severity),
            status=normalize_status_value(status),
            q=q,
            from_ts=parse_datetime_filter(from_ts),
            to_ts=parse_datetime_filter(to_ts, end_of_day=True),
            limit=normalized_limit,
        )

    return {"limit": normalized_limit, "items": records}


@app.get("/reports/alerts")
def get_alerts_report(
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    provider: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
):
    normalized_limit = normalize_limit(limit, default=200, maximum=2000)
    parsed_from = parse_datetime_filter(from_ts)
    parsed_to = parse_datetime_filter(to_ts, end_of_day=True)

    conditions = []
    params: list[Any] = []
    append_time_conditions(conditions, params, "n.sent_at", parsed_from, parsed_to)

    if provider:
        conditions.append("LOWER(COALESCE(n.provider, '')) = LOWER(%s)")
        params.append(provider)
    if status:
        conditions.append("LOWER(n.delivery_status) = LOWER(%s)")
        params.append(status)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(normalized_limit)

    with get_conn() as conn, conn.cursor() as cur:
        ensure_alerts_schema(cur)
        cur.execute(
            f"""
            SELECT
                n.id,
                n.incident_id,
                n.channel,
                n.provider,
                n.delivery_status,
                n.error,
                n.sent_at
            FROM incident_notifications n
            {where_clause}
            ORDER BY n.sent_at DESC
            LIMIT %s
            """,
            params,
        )
        rows = cur.fetchall()

    return {
        "limit": normalized_limit,
        "items": [
            {
                "id": row[0],
                "incident_id": row[1],
                "channel": row[2],
                "provider": row[3],
                "delivery_status": row[4],
                "error": row[5],
                "sent_at": to_iso(row[6]) or "",
            }
            for row in rows
        ],
    }


@app.get("/sla/summary")
def get_sla_summary(
    days: int = 7,
    target_pct: float = 99.0,
):
    window_days = max(1, min(int(days or 7), 365))
    target = max(0.0, min(float(target_pct or 99.0), 100.0))

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            WITH host_availability AS (
                SELECT
                    a.id,
                    a.name,
                    COUNT(m.value) AS samples,
                    AVG(CASE WHEN m.value >= 1 THEN 1.0 ELSE 0.0 END) * 100.0 AS availability_pct
                FROM {ASSETS_TABLE} a
                LEFT JOIN metrics m
                  ON m.asset_id = a.id
                 AND m.metric = 'host.alive'
                 AND m.ts >= now() - (%s::int * interval '1 day')
                WHERE a.enabled = true
                GROUP BY a.id, a.name
            )
            SELECT
                COUNT(*) AS monitored_hosts,
                COUNT(*) FILTER (WHERE samples > 0) AS hosts_with_samples,
                AVG(availability_pct) FILTER (WHERE samples > 0) AS avg_availability_pct,
                COUNT(*) FILTER (WHERE samples > 0 AND availability_pct < %s) AS hosts_below_target
            FROM host_availability
            """,
            (window_days, target),
        )
        sla_row = cur.fetchone()

        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE UPPER(status) IN ('OPEN', 'ACKNOWLEDGED')) AS open_incidents,
                COUNT(*) FILTER (WHERE UPPER(severity) = 'CRITICAL' AND UPPER(status) IN ('OPEN', 'ACKNOWLEDGED')) AS critical_open_incidents
            FROM incidents
            """
        )
        incident_row = cur.fetchone()

        ensure_alerts_schema(cur)
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE delivery_status = 'sent') AS alerts_sent,
                COUNT(*) FILTER (WHERE delivery_status = 'suppressed') AS alerts_suppressed,
                COUNT(*) FILTER (WHERE delivery_status = 'failed') AS alerts_failed
            FROM incident_notifications
            WHERE sent_at >= now() - (%s::int * interval '1 day')
            """,
            (window_days,),
        )
        alert_row = cur.fetchone()

    avg_availability = sla_row[2] if sla_row and sla_row[2] is not None else None
    return {
        "window_days": window_days,
        "target_pct": target,
        "monitored_hosts": int(sla_row[0] or 0),
        "hosts_with_samples": int(sla_row[1] or 0),
        "avg_availability_pct": round(float(avg_availability), 2) if avg_availability is not None else None,
        "hosts_below_target": int(sla_row[3] or 0),
        "open_incidents": int(incident_row[0] or 0),
        "critical_open_incidents": int(incident_row[1] or 0),
        "alerts_sent": int(alert_row[0] or 0),
        "alerts_suppressed": int(alert_row[1] or 0),
        "alerts_failed": int(alert_row[2] or 0),
    }


@app.get("/metrics", response_model=List[MetricOut])
def list_metrics(
    asset_id: Optional[int] = None,
    metric: Optional[str] = None,
    metric_prefix: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 200
):
    with get_conn() as conn, conn.cursor() as cur:
        return select_metric_records(
            cur,
            asset_id=asset_id,
            metric=metric,
            metric_prefix=metric_prefix,
            from_ts=parse_datetime_filter(from_ts),
            to_ts=parse_datetime_filter(to_ts, end_of_day=True),
            limit=limit,
        )


@app.get("/metrics/by-asset/{asset_id}", response_model=List[MetricOut])
def metrics_by_asset(
    asset_id: int,
    metric: Optional[str] = None,
    metric_prefix: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 200
):
    with get_conn() as conn, conn.cursor() as cur:
        return select_metric_records(
            cur,
            asset_id=asset_id,
            metric=metric,
            metric_prefix=metric_prefix,
            from_ts=parse_datetime_filter(from_ts),
            to_ts=parse_datetime_filter(to_ts, end_of_day=True),
            limit=limit,
        )

@app.get("/metrics/latest")
def latest_metrics():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT ON (asset_id, metric)
                    ts, asset_id, metric, value, labels
                FROM metrics
                ORDER BY asset_id, metric, ts DESC
            """)
            rows = cur.fetchall()

    return [
        {
            "ts": r[0].isoformat() if r[0] else "",
            "asset_id": r[1],
            "metric": r[2],
            "value": float(r[3]),
            "labels": r[4] or {},
        }
        for r in rows
    ]

@app.get("/metrics/timeseries", response_model=List[MetricOut])
def metrics_timeseries(
    asset_id: Optional[int] = None,
    metric: Optional[str] = None,
    metric_prefix: Optional[str] = None,
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    limit: int = 500
):
    with get_conn() as conn, conn.cursor() as cur:
        return select_metric_records(
            cur,
            asset_id=asset_id,
            metric=metric,
            metric_prefix=metric_prefix,
            from_ts=parse_datetime_filter(from_ts),
            to_ts=parse_datetime_filter(to_ts, end_of_day=True),
            limit=limit,
        )


@app.get("/audit-logs")
def list_audit_logs(limit: int = Query(100, ge=1, le=500)):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, actor, actor_user_id, actor_email, actor_role, action,
                   target_type, target_id, details, ip_address, user_agent, created_at
            FROM audit_events
            ORDER BY created_at DESC, id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
    return [
        {
            "id": row[0],
            "actor": row[1],
            "actor_user_id": row[2],
            "actor_email": row[3],
            "actor_role": row[4],
            "action": row[5],
            "target_type": row[6],
            "target_id": row[7],
            "details": row[8] or {},
            "ip_address": row[9],
            "user_agent": row[10],
            "created_at": to_iso(row[11]),
        }
        for row in rows
    ]


# =============================
# USERS
# =============================

class UserCreate(BaseModel):
    name: str
    email: str
    role: str = "viewer"
    active: bool = True


def normalize_user_role(role: Optional[str]) -> str:
    normalized = (role or "viewer").strip().lower()
    if normalized not in USER_ROLES:
        raise HTTPException(status_code=400, detail="Papel de usuário inválido.")
    return normalized


def normalize_user_email(email: str) -> str:
    normalized = (email or "").strip().lower()
    if not normalized:
        raise HTTPException(status_code=400, detail="E-mail é obrigatório.")
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", normalized):
        raise HTTPException(status_code=400, detail="E-mail inválido.")
    return normalized


def normalize_user_name(name: str) -> str:
    normalized = (name or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="Nome é obrigatório.")
    return normalized


def generate_temporary_password(length: int = TEMP_PASSWORD_LENGTH) -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(ch.islower() for ch in password)
            and any(ch.isupper() for ch in password)
            and any(ch.isdigit() for ch in password)
        ):
            return password


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    ).hex()
    return f"{PASSWORD_HASH_PREFIX}${PASSWORD_HASH_ITERATIONS}${salt}${digest}"


def verify_password(stored_password: str, candidate_password: str) -> bool:
    stored = stored_password or ""
    candidate = candidate_password or ""
    parts = stored.split("$")
    if len(parts) == 4 and parts[0] == PASSWORD_HASH_PREFIX:
        try:
            iterations = int(parts[1])
            salt = parts[2]
            expected = parts[3]
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                candidate.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            ).hex()
            return hmac.compare_digest(expected, digest)
        except (TypeError, ValueError):
            return False

    # Backward compatible with older plaintext passwords already in the lab DB.
    return hmac.compare_digest(stored, candidate)


def is_hashed_password(stored_password: str) -> bool:
    return str(stored_password or "").startswith(f"{PASSWORD_HASH_PREFIX}$")


def user_out_from_row(row):
    item = {
        "id": row[0],
        "name": row[1],
        "email": row[2],
        "role": row[3],
        "active": row[4],
        "must_change_password": row[5],
    }
    if len(row) > 6:
        item["last_login_at"] = to_iso(row[6])
    if len(row) > 7:
        item["created_at"] = to_iso(row[7])
    if len(row) > 8:
        item["updated_at"] = to_iso(row[8])
    return item


def get_user_row(cur, user_id: int):
    cur.execute(
        """
        SELECT id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    )
    return cur.fetchone()


def ensure_not_last_active_admin(cur, user_id: int) -> None:
    row = get_user_row(cur, user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if row[3] != "admin" or not row[4]:
        return
    cur.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE role = 'admin'
          AND active = true
          AND id <> %s
        """,
        (user_id,),
    )
    other_admins = int(cur.fetchone()[0] or 0)
    if other_admins < 1:
        raise HTTPException(
            status_code=400,
            detail="Não é possível remover ou desativar o último administrador ativo.",
        )


@app.get("/users")
def list_users():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                FROM users
                ORDER BY id
            """)
            rows = cur.fetchall()

            return [user_out_from_row(r) for r in rows]


@app.post("/users")
def create_user(data: UserCreate):
    name = normalize_user_name(data.name)
    email = normalize_user_email(data.email)
    role = normalize_user_role(data.role)
    temporary_password = generate_temporary_password()

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO users (name,email,password,role,active,must_change_password)
                    VALUES (%s,%s,%s,%s,%s,true)
                    RETURNING id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                    """,
                    (name, email, hash_password(temporary_password), role, bool(data.active)),
                )
            except psycopg.errors.UniqueViolation as exc:
                conn.rollback()
                raise HTTPException(status_code=409, detail="Já existe usuário com este e-mail.") from exc

            row = cur.fetchone()
            conn.commit()

            return {
                "user": user_out_from_row(row),
                "temporary_password": temporary_password,
                "must_change_password": True,
            }


@app.put("/users/{user_id}")
def update_user(user_id: int, data: UserCreate):
    name = normalize_user_name(data.name)
    email = normalize_user_email(data.email)
    role = normalize_user_role(data.role)
    active = bool(data.active)

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            current = get_user_row(cur, user_id)
            if current is None:
                raise HTTPException(status_code=404, detail="Usuário não encontrado.")

            if current[3] == "admin" and current[4] and (role != "admin" or not active):
                ensure_not_last_active_admin(cur, user_id)

            try:
                cur.execute(
                    """
                    UPDATE users
                    SET name=%s,email=%s,role=%s,active=%s,updated_at=now()
                    WHERE id=%s
                    RETURNING id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                    """,
                    (name, email, role, active, user_id),
                )
            except psycopg.errors.UniqueViolation as exc:
                conn.rollback()
                raise HTTPException(status_code=409, detail="Já existe usuário com este e-mail.") from exc

            row = cur.fetchone()
            conn.commit()

            return {"ok": True, "user": user_out_from_row(row)}


@app.patch("/users/{user_id}/active")
def set_active(user_id: int, data: dict):
    active = bool(data.get("active"))

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            if not active:
                ensure_not_last_active_admin(cur, user_id)

            cur.execute(
                """
                UPDATE users
                SET active=%s,updated_at=now()
                WHERE id=%s
                RETURNING id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                """,
                (active, user_id),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Usuário não encontrado.")

            conn.commit()

            return {"ok": True, "user": user_out_from_row(row)}


@app.patch("/users/{user_id}/status")
def set_user_status(user_id: int, data: dict):
    if "active" in data:
        active = bool(data.get("active"))
    else:
        status = str(data.get("status") or "").strip().lower()
        if status not in {"active", "inactive", "enabled", "disabled"}:
            raise HTTPException(status_code=400, detail="Informe active=true/false ou status active/inactive.")
        active = status in {"active", "enabled"}
    return set_active(user_id, {"active": active})


@app.patch("/users/{user_id}/reset-password")
def reset_password(user_id: int):
    temporary_password = generate_temporary_password()
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET password=%s, must_change_password=true,updated_at=now()
                WHERE id=%s
                RETURNING id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                """,
                (hash_password(temporary_password), user_id),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Usuário não encontrado.")
            conn.commit()

    return {
        "ok": True,
        "user": user_out_from_row(row),
        "temporary_password": temporary_password,
        "must_change_password": True,
    }


@app.patch("/users/{user_id}/password")
def set_user_password(user_id: int, data: dict):
    supplied_password = str(data.get("new_password") or data.get("password") or "").strip()
    generated = False
    password = supplied_password
    if not password:
        password = generate_temporary_password()
        generated = True
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="A senha deve ter ao menos 6 caracteres.")
    must_change = bool(data.get("must_change_password", generated))

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET password=%s, must_change_password=%s, updated_at=now()
                WHERE id=%s
                RETURNING id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                """,
                (hash_password(password), must_change, user_id),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="UsuÃ¡rio nÃ£o encontrado.")
            conn.commit()

    result = {"ok": True, "user": user_out_from_row(row), "must_change_password": must_change}
    if generated:
        result["temporary_password"] = password
    return result


@app.delete("/users/{user_id}")
def delete_user(user_id: int, actor_user_id: Optional[int] = Query(None)):
    if actor_user_id is not None and int(actor_user_id) == int(user_id):
        raise HTTPException(status_code=400, detail="Você não pode excluir seu próprio usuário.")

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_not_last_active_admin(cur, user_id)
            cur.execute(
                """
                DELETE FROM users
                WHERE id = %s
                RETURNING id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Usuário não encontrado.")
            conn.commit()

    return {"ok": True, "user": user_out_from_row(row)}

# =============================
# AUTH
# =============================

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/auth/login")
def login(data: LoginRequest, request: Request):
    login_email = normalize_user_email(data.email)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, email, role, active, must_change_password, password, last_login_at, created_at, updated_at
                FROM users
                WHERE LOWER(email) = LOWER(%s)
                  AND active = true
                LIMIT 1
                """,
                (login_email,),
            )

            row = cur.fetchone()

            if not row or not verify_password(row[6], data.password):
                log_audit_event(
                    actor={"name": login_email, "email": login_email, "role": "anonymous"},
                    action="auth.login_failed",
                    target_type="users",
                    details={"email": login_email},
                    request=request,
                )
                raise HTTPException(
                    status_code=401,
                    detail="Credenciais inválidas ou usuário inativo."
                )

            if not is_hashed_password(row[6]):
                cur.execute(
                    "UPDATE users SET password = %s WHERE id = %s",
                    (hash_password(data.password), row[0]),
                )
            cur.execute("UPDATE users SET last_login_at=now(), updated_at=now() WHERE id=%s", (row[0],))
            conn.commit()

            user = user_out_from_row((row[0], row[1], row[2], row[3], row[4], row[5], utc_now(), row[8], utc_now()))
            access_token, expires_at = create_access_token(user)
            log_audit_event(
                actor=user,
                action="auth.login_success",
                target_type="users",
                target_id=str(user["id"]),
                details={"email": user["email"], "expires_at": expires_at},
                request=request,
            )

            return {
                **user,
                "user": user,
                "access_token": access_token,
                "token_type": "bearer",
                "expires_at": expires_at,
            }

class ChangePasswordRequest(BaseModel):
    user_id: int
    new_password: str


@app.post("/auth/logout")
def logout(request: Request):
    user = require_request_user(request)
    log_audit_event(
        actor=user,
        action="auth.logout",
        target_type="users",
        target_id=str(user["id"]),
        request=request,
    )
    return {"ok": True}


@app.get("/auth/me")
def auth_me(request: Request):
    return {"user": require_request_user(request)}


@app.post("/auth/change-password")
def change_password(data: ChangePasswordRequest, request: Request):
    if not data.new_password or len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="A senha deve ter ao menos 6 caracteres.")
    if data.new_password == DEFAULT_USER_PASSWORD:
        raise HTTPException(status_code=400, detail="Escolha uma senha diferente da senha padrão.")

    actor = require_request_user(request)
    if actor.get("role") != "admin" and int(actor.get("id")) != int(data.user_id):
        raise HTTPException(status_code=403, detail="Voce nao tem permissao para executar esta acao.")

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET password=%s, must_change_password=false, updated_at=now()
                WHERE id=%s
                  AND active=true
                RETURNING id, name, email, role, active, must_change_password, last_login_at, created_at, updated_at
                """,
                (hash_password(data.new_password), data.user_id),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Usuário ativo não encontrado.")
            conn.commit()

    changed_user = user_out_from_row(row)
    log_audit_event(
        actor=actor,
        action="auth.change_password",
        target_type="users",
        target_id=str(changed_user["id"]),
        details={"self_service": int(actor.get("id")) == int(changed_user["id"])},
        request=request,
    )

    return {"ok": True, "user": changed_user}
