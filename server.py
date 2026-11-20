import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Cookie, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer

from demo_snapshot import ExpiredSnapshot, MAX_TOKEN_LENGTH, WorkspaceFull, restore, snapshot
from fixtures import BENCHMARKS, CATEGORIES, STAGES, TARGETS, TOOLS, evidence_for, in_path


ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get("AUTOTEST_DB", ROOT / ".data" / "workspace.sqlite"))
DSN = os.environ.get("AUTOTEST_DATABASE_URL")
HOSTED = os.environ.get("AUTOTEST_HOSTED") == "1" or (
    os.environ.get("VERCEL") == "1" and os.environ.get("VERCEL_ENV") != "development"
)
DEMO_EMAIL = "demo@autotest.test"
DEMO_PASSWORD = os.environ.get("AUTOTEST_DEMO_PASSWORD", "")
CONFIGURED = not HOSTED or bool(DSN and 16 <= len(DEMO_PASSWORD) <= 128)
DEMO_USER = {"email": DEMO_EMAIL, "name": "Demo Administrator", "role": "Admin"}
PROFILES = ("Full fixture", "Headers only", "Recorded scanner error")
DETECTORS = list(TOOLS)[1:]
COOKIE = "autotest_session"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


class Database:
    def __init__(self, connection, postgres=False):
        self.connection = connection
        self.postgres = postgres

    def execute(self, sql, args=()):
        return self.connection.execute(sql.replace("?", "%s") if self.postgres else sql, args)


demo_database: ContextVar[Database | None] = ContextVar("demo_database", default=None)


def open_database():
    if DSN:
        import psycopg
        from psycopg.rows import dict_row
        connection = psycopg.connect(DSN, row_factory=dict_row, connect_timeout=8)
        return Database(connection, postgres=True)
    DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB, timeout=15)
    connection.row_factory = sqlite3.Row
    return Database(connection)


@contextmanager
def transaction():
    guest = demo_database.get()
    db = guest or open_database()
    connection = db.connection
    try:
        db.execute("SELECT pg_advisory_xact_lock(87652026)" if db.postgres else "BEGIN IMMEDIATE")
        yield db
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        if guest is None:
            connection.close()


def now():
    return time.time()


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def new_id(prefix):
    return f"{prefix}-{secrets.token_hex(3).upper()}"


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def secret_hash(value, salt=None):
    salt = salt or secrets.token_hex(16)
    code = hashlib.pbkdf2_hmac("sha256", value.encode(), bytes.fromhex(salt), 310_000).hex()
    return f"{salt}:{code}"


def matches(value, stored):
    return bool(stored and hmac.compare_digest(secret_hash(value, stored.split(":")[0]), stored))


def put(db, kind, item):
    db.execute(
        "INSERT INTO records (kind,id,body) VALUES (?,?,?) ON CONFLICT (kind,id) DO UPDATE SET body=excluded.body",
        (kind, item["id"], canonical(item)),
    )


def get(db, kind, key):
    row = db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
    return json.loads(row["body"]) if row else None


def records(db, kind):
    data = [json.loads(row["body"]) for row in db.execute("SELECT body FROM records WHERE kind=?", (kind,))]
    return sorted(data, key=lambda item: item.get("created", ""), reverse=True)


def audit(db, actor, action, detail, authorization=None, run=None):
    latest = db.execute("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    payload = {"timestamp": timestamp(now()), "actor": actor, "action": action, "detail": detail,
               "authorization": authorization, "run": run}
    predecessor = latest["hash"] if latest else "0" * 64
    seq = latest["seq"] + 1 if latest else 1
    body = canonical(payload)
    db.execute("INSERT INTO audit (seq,body,hash) VALUES (?,?,?)", (seq, body, digest(f"{predecessor}:{seq}:{body}")))


def audit_view(db):
    previous, valid, events = "0" * 64, True, []
    for index, row in enumerate(db.execute("SELECT * FROM audit ORDER BY seq"), 1):
        valid = valid and row["seq"] == index and row["hash"] == digest(f"{previous}:{index}:{row['body']}")
        previous = row["hash"]
        events.append({"seq": row["seq"], **json.loads(row["body"])})
    return {"valid": valid, "events": events[::-1]}


def saved_authorization(asset, start):
    target = TARGETS[asset]
    return {"id": "AUTH-1001" if asset == "storefront" else "AUTH-1002", "asset": asset, "owner": target["owner"],
            "approver": "Demo Administrator", "path": target["path"], "criticality": .95 if asset == "storefront" else .72,
            "status": "Approved", "start": timestamp(start - 30 * 86400), "end": timestamp(start + 365 * 86400),
            "created": timestamp(start)}


def make_run(run_id, name, auth, url, profile, scanners, started, actor):
    effective = [scanner for scanner in scanners if not (profile == "Recorded scanner error" and scanner == "Nikto")]
    result = evidence_for(auth["asset"], effective, auth["criticality"], profile, urlsplit(url).path)
    deliverable = "Failed" if not effective else ("Partial" if effective != scanners else "Completed")
    return {"id": run_id, "name": name, "authorization": auth["id"], "asset": auth["asset"], "target": url,
            "profile": profile, "scanners": scanners, "created": timestamp(started), "started": started,
            "actor": actor, "result": result, "reviews": {}, "final_status": deliverable, "stored_final": False}


def initialize():
    with transaction() as db:
        db.execute("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, password TEXT, recovery TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, email TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY (kind,id))")
        db.execute("CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY,body TEXT NOT NULL,hash TEXT NOT NULL)")
        if db.postgres:
            db.execute("""CREATE OR REPLACE FUNCTION autotest_keep_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                          BEGIN RAISE EXCEPTION 'Audit is append-only'; END; $$""")
            db.execute("DROP TRIGGER IF EXISTS audit_no_mutation ON audit")
            db.execute("""CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON audit
                          FOR EACH STATEMENT EXECUTE FUNCTION autotest_keep_audit()""")
        else:
            db.execute("""CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
                          BEGIN SELECT RAISE(ABORT, 'Audit is append-only'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
                          BEGIN SELECT RAISE(ABORT, 'Audit is append-only'); END""")
        if db.execute("SELECT email FROM users WHERE email=?", (DEMO_EMAIL,)).fetchone():
            return
        db.execute("INSERT INTO users VALUES (?,?,?,NULL,NULL)", (DEMO_EMAIL, DEMO_USER["name"], DEMO_USER["role"]))
        for index, asset in enumerate(TARGETS, 1):
            started = now() - index * 86400
            auth = saved_authorization(asset, started - 3600)
            put(db, "authorization", auth)
            audit(db, "System", "Authorization seeded", TARGETS[asset]["name"], auth["id"])
            target = TARGETS[asset]
            run = make_run(f"RUN-100{index}", f"{target['name']} baseline", auth,
                           f"https://{target['host']}{target['path']}", PROFILES[0], DETECTORS, started, "System")
            if asset == "portal":
                run["reviews"] = {"banner": "Resolved", "framing": "Resolved"}
            run["stored_final"] = True
            put(db, "run", run)
            audit(db, "System", "Replay completed", run["name"], auth["id"], run["id"])


@asynccontextmanager
async def lifespan(_app):
    if CONFIGURED:
        initialize()
    yield


app = FastAPI(title="AutoTest Research Workbench", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def check_origin(request: Request, call_next):
    local = request.url.hostname in LOCAL_HOSTS
    if not HOSTED and not local:
        return Response("Open the workbench on localhost.", 403)
    origin = request.headers.get("origin")
    scheme = "https" if HOSTED and not local else request.url.scheme
    if request.method not in {"GET", "HEAD"} and origin and origin != f"{scheme}://{request.url.netloc}":
        return Response("Unrecognized request origin.", 403)
    if not CONFIGURED and request.url.path.startswith("/api/") and request.url.path not in {"/api/session", "/api/public-demo"}:
        response = JSONResponse({"detail": "This deployment uses a browser demo workspace."}, 404)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def account(db, token, required=True):
    if demo_database.get() is db:
        return DEMO_USER.copy()
    user = db.execute("SELECT u.email,u.name,u.role FROM users u JOIN sessions s ON u.email=s.email WHERE s.token=? AND s.expires>?",
                      (digest(token or ""), now())).fetchone()
    if HOSTED and user and user["email"] != DEMO_EMAIL:
        user = None
    if required and not user:
        raise HTTPException(401, "Sign in to open the workbench.")
    return dict(user) if user else None


def sign_in(db, user):
    token = secrets.token_urlsafe(32)
    db.execute("DELETE FROM sessions WHERE expires<=?", (now(),))
    db.execute("INSERT INTO sessions VALUES (?,?,?)", (digest(token), user["email"], now() + 43200))
    audit(db, user["email"], "Signed in", user["role"])
    response = JSONResponse({"user": {key: user[key] for key in ("email", "name", "role")}})
    response.set_cookie(COOKIE, token, max_age=43200, httponly=True, secure=HOSTED, samesite="strict")
    return response


class Login(BaseModel):
    email: str = Field(max_length=150)
    password: str = Field(max_length=128)


class Registration(Login):
    name: str = Field(min_length=2, max_length=80)


class Reset(Login):
    recovery: str = Field(min_length=8, max_length=80)


@app.get("/api/session")
def session(autotest_session: str | None = Cookie(None)):
    if not CONFIGURED:
        return {"user": DEMO_USER, "hosted": True, "public_demo": True}
    with transaction() as db:
        return {"user": account(db, autotest_session, False), "hosted": HOSTED, "configured": True}


@app.post("/api/session/demo")
def demo_login():
    if HOSTED:
        raise HTTPException(403, "Sign in with the configured demo password.")
    with transaction() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (DEMO_EMAIL,)).fetchone()
        return sign_in(db, user)


@app.post("/api/session/login")
def login(data: Login):
    email = data.email.strip().lower()
    if HOSTED and (email != DEMO_EMAIL or not hmac.compare_digest(digest(data.password), digest(DEMO_PASSWORD))):
        raise HTTPException(401, "Email or password is incorrect.")
    with transaction() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or (not HOSTED and not matches(data.password, user["password"])):
            raise HTTPException(401, "Email or password is incorrect.")
        return sign_in(db, user)


@app.post("/api/session/register")
def register(data: Registration):
    if HOSTED:
        raise HTTPException(403, "Account registration is available in the local workbench.")
    email = data.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(data.name.strip()) < 2 or len(data.password) < 8:
        raise HTTPException(400, "Enter a name, a valid email, and a password of at least eight characters.")
    recovery = secrets.token_urlsafe(18)
    with transaction() as db:
        if db.execute("SELECT email FROM users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "That email is already registered.")
        db.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                   (email, data.name.strip(), "Security Analyst", secret_hash(data.password), secret_hash(recovery)))
        audit(db, email, "Account registered", "Security Analyst")
    return {"recovery": recovery}


@app.post("/api/session/reset")
def reset(data: Reset):
    if HOSTED:
        raise HTTPException(403, "Update the hosted demo password in deployment settings.")
    if len(data.password) < 8:
        raise HTTPException(400, "Use at least eight characters for the new password.")
    email = data.email.strip().lower()
    with transaction() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not matches(data.recovery.strip(), user["recovery"]):
            raise HTTPException(400, "Email or recovery code is incorrect.")
        db.execute("UPDATE users SET password=? WHERE email=?", (secret_hash(data.password), email))
        db.execute("DELETE FROM sessions WHERE email=?", (email,))
        audit(db, email, "Password reset", "Local recovery code accepted")
    return {"ok": True}


@app.post("/api/session/logout")
def logout(autotest_session: str | None = Cookie(None)):
    with transaction() as db:
        user = account(db, autotest_session, False)
        if user:
            db.execute("DELETE FROM sessions WHERE token=?", (digest(autotest_session),))
            audit(db, user["email"], "Signed out", "Session closed")
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE, httponly=True, secure=HOSTED, samesite="strict")
    return response


class Authorization(BaseModel):
    asset: str
    owner: str = Field(min_length=2, max_length=100)
    path: str = Field(max_length=150)
    criticality: float = Field(ge=0, le=1)
    start: datetime
    end: datetime


class Decision(BaseModel):
    status: str


class Scope(BaseModel):
    authorization: str = Field(max_length=50)
    target: str = Field(max_length=300)


class RunRequest(Scope):
    name: str = Field(min_length=2, max_length=100)
    profile: str
    scanners: list[str] = Field(min_length=1, max_length=3)


class Review(BaseModel):
    decision: str


def safe_path(path):
    return bool(re.fullmatch(r"/[A-Za-z0-9_./-]*", path) and "//" not in path
                and all(segment not in {".", ".."} for segment in path.split("/")))


@app.post("/api/authorizations")
def register_authorization(data: Authorization, autotest_session: str | None = Cookie(None)):
    with transaction() as db:
        user = account(db, autotest_session)
        target = TARGETS.get(data.asset)
        if not target or not safe_path(data.path) or not in_path(data.path, target["path"]):
            raise HTTPException(400, "Choose a fixture asset and a path inside its recorded scope.")
        if not data.start.utcoffset() == timezone.utc.utcoffset(None) or not data.end.utcoffset() == timezone.utc.utcoffset(None) or data.end <= data.start:
            raise HTTPException(400, "Provide a valid testing window in UTC.")
        record = {"id": new_id("AUTH"), "asset": data.asset, "owner": data.owner.strip(), "path": data.path,
                  "criticality": data.criticality, "start": data.start.isoformat(), "end": data.end.isoformat(),
                  "created": timestamp(now()), "status": "Pending", "approver": None}
        if len(record["owner"]) < 2:
            raise HTTPException(400, "Enter the target owner name.")
        put(db, "authorization", record)
        audit(db, user["email"], "Authorization registered", target["name"], record["id"])
        return record


@app.patch("/api/authorizations/{key}")
def decide_authorization(key: str, data: Decision, autotest_session: str | None = Cookie(None)):
    with transaction() as db:
        user = account(db, autotest_session)
        if user["role"] != "Admin":
            raise HTTPException(403, "Only an administrator can approve or reject a scope.")
        record = get(db, "authorization", key)
        if not record:
            raise HTTPException(404, "Authorization record not found.")
        if record["status"] != "Pending" or data.status not in {"Approved", "Rejected"}:
            raise HTTPException(400, "Choose approve or reject for a pending authorization.")
        record.update(status=data.status, approver=user["name"])
        put(db, "authorization", record)
        audit(db, user["email"], f"Authorization {data.status.lower()}", record["path"], key)
        return record


def check_scope(db, user, data):
    auth = get(db, "authorization", data.authorization)
    asset = TARGETS[auth["asset"]] if auth else None
    reason = ""
    if not auth:
        reason = "Authorization ID was not found."
    elif auth["status"] != "Approved":
        reason = "Authorization must be approved."
    elif not datetime.fromisoformat(auth["start"]).timestamp() <= now() <= datetime.fromisoformat(auth["end"]).timestamp():
        reason = "The request is outside the permitted testing window."
    else:
        try:
            if re.search(r"[\s\\%?#]", data.target):
                raise ValueError
            requested = urlsplit(data.target)
            if requested.username is not None or requested.password is not None:
                raise ValueError
            port = 443 if requested.port is None else requested.port
            if requested.scheme != "https" or requested.hostname != asset["host"]:
                reason = "Requested domain or protocol does not match the approved fixture."
            elif port != asset["port"]:
                reason = "Requested port does not match the approved scope."
            elif not safe_path(requested.path) or not in_path(requested.path, auth["path"]):
                reason = "Requested path is outside the approved scope."
        except ValueError:
            reason = "Enter a valid HTTPS fixture URL without credentials, query, or fragment."
    result = {"id": new_id("SCOPE"), "created": timestamp(now()), "target": data.target, "authorization": data.authorization,
              "passed": not reason, "reason": reason, "asset": auth["asset"] if auth else None}
    put(db, "validation", result)
    audit(db, user["email"], "Scope accepted" if not reason else "Scope rejected", reason or data.target, data.authorization)
    return auth, result


@app.post("/api/scope")
def scope(data: Scope, autotest_session: str | None = Cookie(None)):
    with transaction() as db:
        return check_scope(db, account(db, autotest_session), data)[1]


@app.post("/api/runs")
def start_run(data: RunRequest, autotest_session: str | None = Cookie(None)):
    scanners = list(dict.fromkeys(data.scanners))
    if len(data.name.strip()) < 2 or data.profile not in PROFILES or any(tool not in DETECTORS for tool in scanners):
        raise HTTPException(400, "Enter a replay name and choose a valid profile and detector set.")
    with transaction() as db:
        user = account(db, autotest_session)
        auth, result = check_scope(db, user, data)
        if not result["passed"]:
            return JSONResponse({"detail": result["reason"]}, 400)
        job = make_run(new_id("RUN"), data.name.strip(), auth, data.target, data.profile, scanners, now(), user["email"])
        put(db, "run", job)
        audit(db, user["email"], "Replay started", job["name"], auth["id"], job["id"])
        return run_view(db, job)


def run_view(db, job, full=True):
    elapsed = min(STAGES[-1][0], max(0, now() - job["started"]))
    complete = elapsed >= STAGES[-1][0]
    if complete and not job["stored_final"]:
        job["stored_final"] = True
        put(db, "run", job)
        audit(db, "System", f"Replay {job['final_status'].lower()}", job["name"], job["authorization"], job["id"])
    logs = [{"stage": stage, "message": message, "time": timestamp(job["started"] + seconds)}
            for seconds, stage, message in STAGES if seconds <= elapsed]
    if complete and job["final_status"] == "Failed":
        logs[-1] = {**logs[-1], "stage": "Replay failed", "message": "The selected detector fixture contained an adapter error."}
    errors = {"Nikto": "Recorded adapter timeout"} if job["profile"] == "Recorded scanner error" and "Nikto" in job["scanners"] else {}
    raw = job["result"]["raw"]
    tool_states = []
    for index, tool in enumerate(["Nmap", *job["scanners"]]):
        begin, duration = (1, 2) if tool == "Nmap" else (3, 2 + index % 2)
        done = elapsed >= begin + duration
        tool_states.append({"name": tool, "status": ("Failed" if tool in errors else "Completed") if done
                            else ("Running" if elapsed >= begin else "Queued"), "seconds": duration if done else None,
                            "count": (1 if tool == "Nmap" else sum(item["scanner"] == tool for item in raw)) if done else None,
                            "error": errors.get(tool) if done else None})
    findings = []
    for item in job["result"]["findings"]:
        review = job["reviews"].get(item["id"])
        included = (not item["filtered"] and review != "Dismissed") or review in {"Confirmed", "Resolved"}
        findings.append({**item, "review": review, "included": included})
    summary = {"total": sum(item["included"] for item in findings) if complete else 0,
               "resolved": sum(item["review"] == "Resolved" for item in findings) if complete else 0,
               "bands": {band: sum(item["included"] and item["severity"] == band for item in findings) if complete else 0
                         for band in ("Critical", "High", "Medium", "Low")}}
    view = {key: job[key] for key in ("id", "name", "authorization", "asset", "target", "profile", "created")}
    view.update(status=job["final_status"] if complete else "Running", progress=int(100 * elapsed / STAGES[-1][0]),
                completed=timestamp(job["started"] + STAGES[-1][0]) if complete else None, stage=logs[-1]["stage"],
                observed=sum(item["count"] or 0 for item in tool_states if item["name"] != "Nmap"), summary=summary,
                tools=tool_states)
    if full:
        view.update(logs=logs, recon=TARGETS[job["asset"]] if elapsed >= 3 else None,
                    stages={"raw": raw if elapsed >= 6 else [], "normalized": job["result"]["normalized"] if elapsed >= 7 else [],
                            "findings": findings if complete else []})
    return view


@app.get("/api/workspace")
def workspace(autotest_session: str | None = Cookie(None)):
    with transaction() as db:
        user = account(db, autotest_session)
        return {"user": user, "hosted": HOSTED, "targets": TARGETS, "tools": TOOLS, "profiles": PROFILES,
                "database": "Browser demo workspace" if demo_database.get() is db else ("PostgreSQL" if db.postgres else "SQLite"),
                "authorizations": records(db, "authorization"), "validations": records(db, "validation"),
                "runs": [run_view(db, job, False) for job in records(db, "run")],
                "audit": audit_view(db), "benchmarks": BENCHMARKS, "categories": CATEGORIES}


def require_run(db, key):
    job = get(db, "run", key)
    if not job:
        raise HTTPException(404, "Replay record not found.")
    return job


@app.get("/api/runs/{key}")
def get_run(key: str, autotest_session: str | None = Cookie(None)):
    with transaction() as db:
        account(db, autotest_session)
        return run_view(db, require_run(db, key))


@app.patch("/api/runs/{key}/findings/{finding}")
def review_finding(key: str, finding: str, data: Review, autotest_session: str | None = Cookie(None)):
    with transaction() as db:
        user = account(db, autotest_session)
        job = require_run(db, key)
        if data.decision not in {"Confirmed", "Dismissed", "Resolved", "Clear"}:
            raise HTTPException(400, "Unknown review decision.")
        item = next((item for item in run_view(db, job)["stages"]["findings"] if item["id"] == finding), None)
        if not item:
            raise HTTPException(404, "Finding is unavailable.")
        if data.decision == "Resolved" and not item["included"]:
            raise HTTPException(400, "Confirm a held finding before marking it resolved.")
        if data.decision == "Clear":
            job["reviews"].pop(finding, None)
        else:
            job["reviews"][finding] = data.decision
        put(db, "run", job)
        audit(db, user["email"], "Finding reviewed", f"{item['title']} — {data.decision}", job["authorization"], key)
        return run_view(db, job)


def report_sections(run):
    findings = [row for row in run["stages"]["findings"] if row["included"]]
    held = len(run["stages"]["findings"]) - len(findings)
    bands = ", ".join(f"{count} {band.lower()}" for band, count in run["summary"]["bands"].items())
    sections = [
        ("Executive summary", [f"{len(findings)} findings in the report, {held} held or dismissed. Risk distribution: {bands}.",
                              f"Target: {run['target']}", f"Authorization: {run['authorization']} · Status: {run['status']}",
                              f"Completed: {run['completed']}", "Evidence comes from fixed research fixtures."]),
        ("Risk assessment", ["Composite risk = confidence × (0.40 × CVSS/10 + 0.25 × exploit factor + 0.20 × asset criticality + 0.15 × business impact)."]),
    ]
    for index, item in enumerate(findings, 1):
        sections.append((f"{index}. {item['title']}", [
            f"{item['severity']} · Risk {item['score']:.3f} · CVSS {item['cvss']:.1f} · Confidence {item['gamma']:.0%}",
            f"{item['cwe']} · CVE {item['cve'] or 'unassigned'} · Endpoint {item['endpoint']}",
            f"Sources: {', '.join(item['sources'])} · Verification: {item['verification']} · Analyst review: {item['review'] or 'Pending'}",
            f"Evidence: {item['evidence']}", f"Remediation: {item['remediation']}",
        ]))
    return sections


@app.get("/api/runs/{key}/export/{format}")
def export_report(key: str, format: str, autotest_session: str | None = Cookie(None)):
    if format not in {"pdf", "html"}:
        raise HTTPException(404, "Report format not found.")
    with transaction() as db:
        user = account(db, autotest_session)
        run = run_view(db, require_run(db, key))
        if run["status"] not in {"Completed", "Partial"}:
            raise HTTPException(409, "A report is available after a successful or partial replay.")
        sections = report_sections(run)
        if format == "html":
            body = "".join(f"<section><h2>{escape(title)}</h2>{''.join(f'<p>{escape(line)}</p>' for line in lines)}</section>"
                           for title, lines in sections)
            content = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
                <title>{escape(run["name"])} | AutoTest</title><style>body{{font:16px/1.55 system-ui;color:#18231e;margin:3rem auto;
                max-width:50rem;padding:0 1.3rem}}h2{{font-size:1.2rem;border-top:1px solid #dce2dc;padding-top:1rem}}p{{margin:.45rem 0}}
                section{{margin-bottom:1.8rem}}h1{{margin:0}}</style><body><p>AutoTest · Research replay · {escape(key)}</p>
                <h1>{escape(run["name"])}</h1>{body}</body></html>""".encode()
            media = "text/html"
        else:
            buffer = BytesIO()
            document = SimpleDocTemplate(buffer, title=run["name"], author="AutoTest Research Workbench",
                                         leftMargin=.7 * inch, rightMargin=.7 * inch)
            styles = getSampleStyleSheet()
            styles["Heading2"].textColor = colors.HexColor("#24634b")
            story = [Paragraph(escape(run["name"]), styles["Title"]),
                     Paragraph(f"AutoTest Research replay | {escape(key)}", styles["Normal"]), Spacer(1, 12)]
            for title, lines in sections:
                section = [Paragraph(escape(title), styles["Heading2"])]
                for line in lines:
                    section.extend([Paragraph(escape(line), styles["Normal"]), Spacer(1, 5)])
                story.append(KeepTogether(section))
            document.build(story)
            content, media = buffer.getvalue(), "application/pdf"
        audit(db, user["email"], "Report exported", format.upper(), run["authorization"], key)
        return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="AutoTest-{key}.{format}"'})


class DemoCommand(BaseModel):
    method: str = Field(max_length=5)
    path: str = Field(max_length=150)
    state: str = Field(default="", max_length=MAX_TOKEN_LENGTH)
    data: dict | None = None


DEMO_ROUTES = (
    ("GET", re.compile("/workspace"), workspace, None),
    ("POST", re.compile("/authorizations"), register_authorization, Authorization),
    ("PATCH", re.compile(r"/authorizations/([A-Z0-9-]{1,40})"), decide_authorization, Decision),
    ("POST", re.compile("/scope"), scope, Scope),
    ("POST", re.compile("/runs"), start_run, RunRequest),
    ("GET", re.compile(r"/runs/([A-Z0-9-]{1,40})"), get_run, None),
    ("PATCH", re.compile(r"/runs/([A-Z0-9-]{1,40})/findings/([a-z0-9-]{1,40})"), review_finding, Review),
    ("GET", re.compile(r"/runs/([A-Z0-9-]{1,40})/export/(pdf|html)"), export_report, None),
)


def demo_operation(command, route):
    _, pattern, endpoint, model = route
    args = list(pattern.fullmatch(command.path).groups())
    if model:
        args.append(model.model_validate(command.data or {}))
    return endpoint(*args, autotest_session=None)


@app.post("/api/public-demo")
def public_demo(command: DemoCommand):
    if CONFIGURED:
        raise HTTPException(404, "Browser demo is unavailable in this workspace.")
    route = next((item for item in DEMO_ROUTES if command.method == item[0] and item[1].fullmatch(command.path)), None)
    if not route:
        raise HTTPException(404, "Unknown demo operation.")

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    context = demo_database.set(Database(connection))
    try:
        if command.state:
            restore(connection, command.state)
        else:
            initialize()
        try:
            result = demo_operation(command, route)
        except ValidationError:
            raise HTTPException(422, "Check the required fields and try again.") from None
        envelope = {}
        status = 200
        if isinstance(result, JSONResponse):
            status = result.status_code
            envelope.update(json.loads(result.body))
        elif isinstance(result, Response):
            envelope["file"] = {"body": base64.b64encode(result.body).decode("ascii"), "type": result.media_type}
        else:
            envelope["result"] = result
        if not command.state or connection.total_changes:
            envelope["state"] = snapshot(connection)
        return JSONResponse(envelope, status_code=status)
    except ExpiredSnapshot:
        return JSONResponse({"code": "expired_demo", "detail": "The browser demo has a new version."}, status_code=409)
    except WorkspaceFull:
        raise HTTPException(413, "This demo tab has reached its storage limit. Open the demo in a new tab to continue.") from None
    finally:
        demo_database.reset(context)
        connection.close()


@app.get("/api/public-demo")
def open_public_demo():
    return public_demo(DemoCommand(method="GET", path="/workspace"))


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/index.html", methods=["GET", "HEAD"], include_in_schema=False)
def frontend():
    # Always deliver the entry document for the current deployment. Its hashed
    # asset URLs change whenever the compiled interface changes.
    index = ROOT / "dist" / "index.html"
    if not index.is_file():
        raise HTTPException(503, "Build the React frontend before opening the workspace.")
    content = index.read_bytes()
    fingerprint = hashlib.sha256(content).hexdigest()
    return Response(content, media_type="text/html", headers={"Cache-Control": "no-store", "ETag": f'"{fingerprint}"'})


app.mount("/", StaticFiles(directory=ROOT / "dist", check_dir=False), name="frontend-assets")
