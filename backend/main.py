"""
backend/main.py
─────────────────────────────────────────────────────────────────────────────
FastAPI backend for the Behavioural Detection Engine.

Responsibilities
────────────────
  • Persist incoming events to SQLite via SQLAlchemy ORM
  • Pass each event through the detection engine (Phase 3)
  • Persist any resulting Alert to SQLite
  • Serve all stored alerts via a GET endpoint
  • Allow cross-origin requests from the React dev server on port 5173

Endpoints
─────────
  POST /events          Receive an event, run detection, save both to DB
  GET  /alerts          Return all persisted alerts (newest first)
  GET  /alerts/{id}     Return a single alert by primary key
  GET  /events          Return all persisted events (newest first, paginated)
  GET  /health          Liveness check

Run
───
  cd behavioral-detection-engine
  uvicorn backend.main:app --reload --port 8000

  Or from inside the backend/ directory:
  uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import json
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Ensure sibling packages (detection/) are importable ───────────────────────
_ROOT = Path(__file__).resolve().parent.parent   # behavioral-detection-engine/
sys.path.insert(0, str(_ROOT))

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy import String, Integer, Float, Text, DateTime

from detection.engine import DetectionEngine, Alert as EngineAlert

# =============================================================================
# Database setup
# =============================================================================

_DB_PATH   = _ROOT / "backend" / "detection.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},   # required for SQLite + FastAPI
    echo=False,
)

# Enable WAL mode for better concurrent read performance with SQLite
@sa_event.listens_for(engine, "connect")
def _set_wal(dbapi_connection, _connection_record):
    dbapi_connection.execute("PRAGMA journal_mode=WAL;")
    dbapi_connection.execute("PRAGMA foreign_keys=ON;")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# =============================================================================
# SQLAlchemy ORM models
# =============================================================================

class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    """Persisted copy of a raw telemetry event."""

    __tablename__ = "events"

    id: Mapped[int]            = mapped_column(Integer, primary_key=True, index=True)
    event_id: Mapped[str]      = mapped_column(String(36), unique=True, index=True)
    timestamp: Mapped[datetime]= mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(tz=timezone.utc),
    )
    host: Mapped[str]          = mapped_column(String(128), index=True)
    user: Mapped[str]          = mapped_column(String(128))
    process: Mapped[str]       = mapped_column(String(128))
    parent_process: Mapped[str]= mapped_column(String(128))
    command: Mapped[str]       = mapped_column(Text)
    source: Mapped[str]        = mapped_column(String(64), index=True)
    severity: Mapped[str]      = mapped_column(String(16))
    # Full raw JSON payload stored for completeness / replay
    raw_json: Mapped[str]      = mapped_column(Text)
    # Score produced by the Scorer for this single event (sum of rule scores)
    event_score: Mapped[int]   = mapped_column(Integer, default=0)
    # Number of rules that matched this event
    rules_matched: Mapped[int] = mapped_column(Integer, default=0)


class AlertRecord(Base):
    """Persisted alert emitted by the Correlator when a host breaches the threshold."""

    __tablename__ = "alerts"

    id: Mapped[int]                = mapped_column(Integer, primary_key=True, index=True)
    alert_id: Mapped[str]          = mapped_column(String(36), unique=True, index=True)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    host: Mapped[str]              = mapped_column(String(128), index=True)
    cumulative_score: Mapped[int]  = mapped_column(Integer)
    threshold: Mapped[int]         = mapped_column(Integer)
    window_seconds: Mapped[int]    = mapped_column(Integer)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime]   = mapped_column(DateTime(timezone=True))
    # JSON arrays / objects serialised to text
    mitre_techniques: Mapped[str]  = mapped_column(Text)   # JSON list
    families: Mapped[str]          = mapped_column(Text)   # JSON list
    reason: Mapped[str]            = mapped_column(Text)
    contributing_rules: Mapped[str]= mapped_column(Text)   # JSON list of rule dicts
    # Denormalised alert_type for quick filtering
    alert_type: Mapped[str]        = mapped_column(
        String(64), default="HOST_THRESHOLD_BREACH"
    )


# Create tables on startup
Base.metadata.create_all(bind=engine)


# =============================================================================
# Detection engine — module-level singleton (loaded once at startup)
# =============================================================================

_RULES_PATH = _ROOT / "detection" / "rules.json"

_detection_engine: DetectionEngine | None = None


def get_detection_engine() -> DetectionEngine:
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine(rules_path=_RULES_PATH)
    return _detection_engine


# =============================================================================
# Pydantic schemas
# =============================================================================

# ── Inbound ───────────────────────────────────────────────────────────────────

class EventIn(BaseModel):
    """Schema for the POST /events request body.

    All seven required schema fields must be present.  Optional enrichment
    fields (pid, ppid, severity, tags, extra, event_id) are accepted and
    passed through to the detection engine.
    """

    # Required fields (schema contract from simulator/base.py)
    timestamp:      str  = Field(..., description="ISO-8601 UTC timestamp, e.g. '2026-09-20T16:08:35.107Z'")
    host:           str  = Field(..., min_length=1, description="Hostname")
    user:           str  = Field(..., min_length=1, description="Username / security context")
    process:        str  = Field(..., min_length=1, description="Spawned process image name")
    parent_process: str  = Field(..., min_length=1, description="Parent process image name")
    command:        str  = Field(..., min_length=1, description="Full command-line string")
    source:         str  = Field(..., min_length=1, description="Telemetry source identifier")

    # Optional enrichment fields (passed through to engine unchanged)
    event_id:  str | None        = Field(default=None, description="UUID for the event; auto-generated if absent")
    pid:       int | None        = Field(default=None)
    ppid:      int | None        = Field(default=None)
    severity:  str               = Field(default="info")
    tags:      list[str]         = Field(default_factory=list)
    extra:     dict[str, Any]    = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        allowed = {"info", "low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}, got {v!r}")
        return v

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"timestamp must be an ISO-8601 string, got {v!r}")
        return v

    def to_engine_dict(self) -> dict[str, Any]:
        """Return a plain dict suitable for passing to DetectionEngine.process()."""
        d = self.model_dump(exclude_none=False)
        if not d.get("event_id"):
            d["event_id"] = str(uuid.uuid4())
        return d

    model_config = {"json_schema_extra": {
        "example": {
            "timestamp": "2026-09-20T16:08:35.107Z",
            "host": "WKSTN-ALPHA",
            "user": "jsmith",
            "process": "powershell.exe",
            "parent_process": "WINWORD.EXE",
            "command": "powershell.exe -nop -w hidden -enc cwBlAGsA...",
            "source": "powershell_macro",
            "severity": "high",
            "tags": ["T1059.001", "macro"],
        }
    }}


# ── Outbound — Event ──────────────────────────────────────────────────────────

class ContributingRule(BaseModel):
    rule_id:   str
    rule_name: str
    score:     int
    event_id:  str
    timestamp: str


class AlertOut(BaseModel):
    """Response model for a single persisted alert."""

    id:                int
    alert_id:          str
    alert_type:        str
    triggered_at:      str
    host:              str
    cumulative_score:  int
    threshold:         int
    window_seconds:    int
    window_start:      str
    window_end:        str
    mitre_techniques:  list[str]
    families:          list[str]
    reason:            str
    contributing_rules: list[ContributingRule]

    model_config = {"from_attributes": True}

    @classmethod
    def from_record(cls, rec: AlertRecord) -> "AlertOut":
        return cls(
            id               = rec.id,
            alert_id         = rec.alert_id,
            alert_type       = rec.alert_type,
            triggered_at     = rec.triggered_at.isoformat(),
            host             = rec.host,
            cumulative_score = rec.cumulative_score,
            threshold        = rec.threshold,
            window_seconds   = rec.window_seconds,
            window_start     = rec.window_start.isoformat(),
            window_end       = rec.window_end.isoformat(),
            mitre_techniques = json.loads(rec.mitre_techniques),
            families         = json.loads(rec.families),
            reason           = rec.reason,
            contributing_rules = [
                ContributingRule(**r)
                for r in json.loads(rec.contributing_rules)
            ],
        )


class EventOut(BaseModel):
    """Response model for a single persisted event."""

    id:             int
    event_id:       str
    timestamp:      str
    received_at:    str
    host:           str
    user:           str
    process:        str
    parent_process: str
    command:        str
    source:         str
    severity:       str
    event_score:    int
    rules_matched:  int

    model_config = {"from_attributes": True}

    @classmethod
    def from_record(cls, rec: EventRecord) -> "EventOut":
        return cls(
            id             = rec.id,
            event_id       = rec.event_id,
            timestamp      = rec.timestamp.isoformat(),
            received_at    = rec.received_at.isoformat(),
            host           = rec.host,
            user           = rec.user,
            process        = rec.process,
            parent_process = rec.parent_process,
            command        = rec.command,
            source         = rec.source,
            severity       = rec.severity,
            event_score    = rec.event_score,
            rules_matched  = rec.rules_matched,
        )


class EventResponse(BaseModel):
    """Full response for POST /events."""

    event:   EventOut
    alert:   AlertOut | None = None
    message: str


class AlertsListResponse(BaseModel):
    total:  int
    alerts: list[AlertOut]


class EventsListResponse(BaseModel):
    total:  int
    events: list[EventOut]


class HealthResponse(BaseModel):
    status:       str
    rules_loaded: int
    db_path:      str


class ErrorDetail(BaseModel):
    detail: str


# =============================================================================
# FastAPI app
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-warm the detection engine on startup so the first request is fast."""
    get_detection_engine()   # loads + compiles all 24 rules
    yield


app = FastAPI(
    title="Behavioural Detection Engine API",
    description=(
        "Receives telemetry events, runs them through the detection engine, "
        "persists events and alerts to SQLite, and exposes a query interface "
        "for a React dashboard."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite React dev server
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Dependency — database session
# =============================================================================

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =============================================================================
# Helper — persist engine Alert → AlertRecord
# =============================================================================

def _alert_to_record(engine_alert: EngineAlert) -> AlertRecord:
    """Convert a detection-engine Alert dataclass into an ORM AlertRecord."""
    contributing = [
        {
            "rule_id"  : m.rule.id,
            "rule_name": m.rule.name,
            "score"    : m.rule.score,
            "event_id" : m.event_id,
            "timestamp": m.timestamp.isoformat(),
        }
        for m in engine_alert.matches
    ]
    return AlertRecord(
        alert_id          = str(uuid.uuid4()),
        triggered_at      = engine_alert.triggered_at,
        host              = engine_alert.host,
        cumulative_score  = engine_alert.cumulative_score,
        threshold         = engine_alert.threshold,
        window_seconds    = engine_alert.window_seconds,
        window_start      = engine_alert.window_start,
        window_end        = engine_alert.window_end,
        mitre_techniques  = json.dumps(engine_alert.mitre_techniques),
        families          = json.dumps(sorted(engine_alert.families)),
        reason            = engine_alert.reason,
        contributing_rules= json.dumps(contributing),
        alert_type        = "HOST_THRESHOLD_BREACH",
    )


def _parse_dt(ts_str: str) -> datetime:
    """Parse ISO-8601 string → timezone-aware datetime."""
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


# =============================================================================
# Endpoints
# =============================================================================

@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    tags=["ops"],
)
def health_check() -> HealthResponse:
    eng = get_detection_engine()
    return HealthResponse(
        status       = "ok",
        rules_loaded = eng.scorer.rule_count,
        db_path      = str(_DB_PATH),
    )


# ── POST /events ─────────────────────────────────────────────────────────────

@app.post(
    "/events",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a telemetry event",
    description=(
        "Receives a single structured event, runs it through the detection engine, "
        "saves the event (and any resulting alert) to SQLite, and returns both "
        "in the response body."
    ),
    responses={
        422: {"model": ErrorDetail, "description": "Validation error"},
        500: {"model": ErrorDetail, "description": "Internal engine error"},
    },
    tags=["events"],
)
def ingest_event(
    payload: EventIn,
    db:      Session = Depends(get_db),
) -> EventResponse:
    """
    Ingest one event into the detection pipeline.

    - Validates all required schema fields (returns 422 on failure).
    - Converts the Pydantic model to a plain dict and calls `engine.process()`.
    - Persists the raw event record to the `events` table.
    - If the detection engine produces an Alert, persists it to the `alerts` table.
    - Returns the saved event row and (optionally) the alert.
    """
    eng = get_detection_engine()

    # 1. Convert to engine dict (auto-assigns event_id if missing)
    event_dict = payload.to_engine_dict()
    event_id   = event_dict["event_id"]

    # 2. Run through detection engine
    try:
        # Scorer scores the event; Correlator checks the per-host window
        matches      = eng.scorer.score_event(event_dict)
        event_score  = eng.scorer.total_score(matches)
        engine_alert = eng.correlator.ingest(matches)
        if engine_alert:
            eng._alert_count += 1   # keep stats in sync
        eng._processed += 1
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection engine error: {exc}",
        ) from exc

    # 3. Persist event
    event_record = EventRecord(
        event_id       = event_id,
        timestamp      = _parse_dt(payload.timestamp),
        received_at    = datetime.now(tz=timezone.utc),
        host           = payload.host,
        user           = payload.user,
        process        = payload.process,
        parent_process = payload.parent_process,
        command        = payload.command,
        source         = payload.source,
        severity       = payload.severity,
        raw_json       = json.dumps(event_dict, ensure_ascii=False),
        event_score    = event_score,
        rules_matched  = len(matches),
    )
    db.add(event_record)

    # 4. Persist alert (if any)
    alert_record: AlertRecord | None = None
    if engine_alert is not None:
        alert_record = _alert_to_record(engine_alert)
        db.add(alert_record)

    try:
        db.commit()
        db.refresh(event_record)
        if alert_record:
            db.refresh(alert_record)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database write failed: {exc}",
        ) from exc

    return EventResponse(
        event   = EventOut.from_record(event_record),
        alert   = AlertOut.from_record(alert_record) if alert_record else None,
        message = (
            f"Alert raised for host '{payload.host}' (score {engine_alert.cumulative_score})"
            if engine_alert
            else "Event ingested. No alert threshold breached."
        ),
    )


# ── GET /alerts ───────────────────────────────────────────────────────────────

@app.get(
    "/alerts",
    response_model=AlertsListResponse,
    summary="Fetch all alerts",
    description="Returns all persisted alerts ordered by triggered_at descending (newest first). Supports optional host filtering and pagination.",
    tags=["alerts"],
)
def list_alerts(
    host:   str | None = Query(default=None, description="Filter by host name"),
    limit:  int        = Query(default=100, ge=1, le=1000, description="Max results to return"),
    offset: int        = Query(default=0,   ge=0,          description="Pagination offset"),
    db:     Session    = Depends(get_db),
) -> AlertsListResponse:
    query = db.query(AlertRecord).order_by(AlertRecord.triggered_at.desc())
    if host:
        query = query.filter(AlertRecord.host == host)

    total   = query.count()
    records = query.offset(offset).limit(limit).all()

    return AlertsListResponse(
        total  = total,
        alerts = [AlertOut.from_record(r) for r in records],
    )


@app.get(
    "/alerts/{alert_id}",
    response_model=AlertOut,
    summary="Fetch a single alert by ID",
    responses={404: {"model": ErrorDetail, "description": "Alert not found"}},
    tags=["alerts"],
)
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertOut:
    record = db.get(AlertRecord, alert_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )
    return AlertOut.from_record(record)


# ── GET /events ───────────────────────────────────────────────────────────────

@app.get(
    "/events",
    response_model=EventsListResponse,
    summary="Fetch all ingested events",
    description="Returns persisted events ordered by timestamp descending. Supports host and source filtering and pagination.",
    tags=["events"],
)
def list_events(
    host:   str | None = Query(default=None, description="Filter by host name"),
    source: str | None = Query(default=None, description="Filter by source identifier"),
    limit:  int        = Query(default=100, ge=1, le=1000),
    offset: int        = Query(default=0,   ge=0),
    db:     Session    = Depends(get_db),
) -> EventsListResponse:
    query = db.query(EventRecord).order_by(EventRecord.timestamp.desc())
    if host:
        query = query.filter(EventRecord.host == host)
    if source:
        query = query.filter(EventRecord.source == source)

    total   = query.count()
    records = query.offset(offset).limit(limit).all()

    return EventsListResponse(
        total  = total,
        events = [EventOut.from_record(r) for r in records],
    )

