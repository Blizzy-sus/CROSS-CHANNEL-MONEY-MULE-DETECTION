import hashlib
from pathlib import Path

from fastapi import Body, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import threading
import pandas as pd
import math

from backend.realtime_engine import RealTimeEngine
from backend.ledger_ws import pump_ledger

app = FastAPI()

_STATIC = Path(__file__).resolve().parent.parent / "static" / "ledger"
if _STATIC.is_dir():
    app.mount(
        "/ledger-ui",
        StaticFiles(directory=str(_STATIC), html=True),
        name="ledger_ui",
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = RealTimeEngine()
threading.Thread(target=engine.run, daemon=True).start()


def _clean(records):
    cleaned = []
    for row in records:
        clean_row = {}
        for k, v in row.items():
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                clean_row[k] = None
            else:
                clean_row[k] = v
        cleaned.append(clean_row)
    return cleaned


def _stable_pos(account_id: str, spread_x: float = 900.0, spread_y: float = 620.0):
    """Same deterministic position formula used by the frontend."""
    h = hashlib.md5(str(account_id).encode()).hexdigest()
    x = (int(h[0:4], 16) / 65535.0) * spread_x
    y = (int(h[4:8], 16) / 65535.0) * spread_y
    return round(x, 1), round(y, 1)


@app.get("/accounts")
def get_accounts():
    df = engine.get_accounts()
    if "creation_time" in df.columns:
        df["creation_time"] = df["creation_time"].astype(str)
    return _clean(df.to_dict(orient="records"))


@app.get("/transactions")
def get_transactions():
    records = engine.get_transactions()
    for r in records:
        if "timestamp" in r and not isinstance(r["timestamp"], str):
            r["timestamp"] = str(r["timestamp"])
    return _clean(records)


@app.get("/all_transactions")
def get_all_transactions():
    df = engine.get_all_transactions()
    if "timestamp" in df.columns:
        df["timestamp"] = df["timestamp"].astype(str)
    return _clean(df.to_dict(orient="records"))


@app.get("/transaction_count")
def get_transaction_count():
    with engine.lock:
        return {"count": len(engine.transactions_df)}


# ── REAL METRICS — all numbers from engine state ──────────────────
@app.get("/metrics")
def get_metrics():
    with engine.lock:
        tx_count  = len(engine.transactions_df)
        active_ct = int(engine.accounts_df["is_active"].sum()) \
                    if "is_active" in engine.accounts_df.columns \
                    else len(engine.accounts_df)
        fraud_ct  = int((engine.accounts_df["is_fraud"] == 1).sum()) \
                    if "is_fraud" in engine.accounts_df.columns else 0
        total_ct  = len(engine.accounts_df)

    sus_scores = engine.get_suspicion_scores()
    sus_count  = len([s for s in sus_scores.values() if s >= 0.25])

    return {
        "tps":              engine.get_real_tps(),
        "tx_count":         tx_count,
        "fraud_count":      fraud_ct,
        "active_accounts":  active_ct,
        "total_accounts":   total_ct,
        "banned_count":     len(engine.banned_accounts),
        "suspicious_count": sus_count,
    }


# ── SUSPICION SCORES ──────────────────────────────────────────────
@app.get("/suspicion_scores")
def get_suspicion_scores():
    scores = engine.compute_suspicion_scores()
    return {k: float(v) for k, v in scores.items()}


@app.get("/suspicious_accounts")
def get_suspicious_accounts():
    from backend.config import EARLY_DETECTION_TOP_PCT
    return engine.get_suspicious_accounts(top_pct=EARLY_DETECTION_TOP_PCT)


# ── NEW ACCOUNT CREATION ──────────────────────────────────────────
@app.post("/create_account")
def create_account():
    """
    Creates a new account in the engine and returns its ID plus the
    deterministic canvas position so the frontend can place the node.
    """
    acc_id = engine.create_account()
    x, y   = _stable_pos(acc_id)
    return {
        "account_id": acc_id,
        "x":          x,
        "y":          y,
        "status":     "normal",
        "suspicion":  0,
        "createdAt":  pd.Timestamp.now().isoformat(),
    }


# ── TRIGGER ATTACK ────────────────────────────────────────────────
@app.get("/trigger_attack")
def trigger_attack(index: int = 0):
    try:
        attack_name, attack_time = engine.trigger_attack(attack_index=index)
        if attack_name is None:
            return {"status": "skipped", "reason": "not enough active accounts"}
        df = engine.get_accounts()
        if "creation_time" in df.columns:
            df["creation_time"] = df["creation_time"].astype(str)
        return {
            "status":      "attack triggered",
            "attack_name": attack_name,
            "attack_time": str(attack_time),
            "accounts":    _clean(df.to_dict(orient="records")),
        }
    except Exception as e:
        import traceback
        return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}


# ── FRAUD GROUND TRUTH ────────────────────────────────────────────
@app.get("/fraud_gt")
def get_fraud_gt():
    return engine.get_fraud_accounts()


# ── BAN ACCOUNTS ──────────────────────────────────────────────────
@app.post("/ban_accounts")
def ban_accounts(account_ids: list = Body(...)):
    engine.ban_accounts(account_ids)
    return {
        "status":           "banned",
        "banned":           account_ids,
        "remaining_active": engine.get_active_count(),
    }


# ── RESET STATE ───────────────────────────────────────────────────
@app.get("/reset_state")
def reset_state():
    engine.reset_state()
    return {"status": "reset"}


# ── LATEST ATTACK — nodes + transactions for Graph 2 ─────────────
@app.get("/latest_attack")
def get_latest_attack():
    """Returns nodes and ordered transactions involved in the most recent attack."""
    attack_name = engine.last_attack_name
    if not attack_name:
        return {"attack_name": None, "nodes": [], "edges": []}

    with engine.lock:
        acc_df = engine.accounts_df.copy()
        tx_df  = engine.transactions_df.copy()

    # Fraud nodes
    fraud_ids = set(
        acc_df[acc_df["is_fraud"] == 1]["account_id"].astype(str).tolist()
        if "is_fraud" in acc_df.columns else []
    )

    # Attack transactions — ordered chronologically
    if "is_attack" in tx_df.columns:
        atk_tx = tx_df[tx_df["is_attack"] == True].copy()
    else:
        atk_tx = tx_df[
            tx_df["sender"].astype(str).isin(fraud_ids) |
            tx_df["receiver"].astype(str).isin(fraud_ids)
        ].tail(60).copy()

    # Sort by timestamp so replay is chronological
    if "timestamp" in atk_tx.columns:
        atk_tx = atk_tx.sort_values("timestamp")

    # Collect involved node IDs
    involved = set()
    edges = []
    for _, row in atk_tx.iterrows():
        s = str(row.get("sender",  ""))
        r = str(row.get("receiver", ""))
        if not s or not r:
            continue
        involved.add(s)
        involved.add(r)
        ts = row.get("timestamp", "")
        edges.append({
            "source":    s,
            "target":    r,
            "amount":    float(row.get("amount", 0)),
            "channel":   str(row.get("channel", "")),
            "timestamp": str(ts),
        })

    # Build node list
    sus_scores = engine.get_suspicion_scores()
    nodes = []
    for _, row in acc_df[acc_df["account_id"].astype(str).isin(involved)].iterrows():
        aid      = str(row["account_id"])
        is_fraud = str(row.get("is_fraud", 0)) == "1"
        x, y     = _stable_pos(aid)
        nodes.append({
            "id":        aid,
            "channel":   str(row.get("channel", "")),
            "role":      "fraud" if is_fraud else "suspicious",
            "sus_score": round(float(sus_scores.get(aid, 0.0)), 3),
            "x":         x,
            "y":         y,
        })

    return {
        "attack_name": attack_name,
        "nodes":       _clean(nodes),
        "edges":       _clean(edges),
    }


# ── CHANNEL FILTER ────────────────────────────────────────────────
_channel_filter: dict = {"channel": None}


@app.get("/channel_filter")
def get_channel_filter():
    return _channel_filter


@app.post("/channel_filter")
def set_channel_filter(body: dict = Body(...)):
    ch = body.get("channel")
    _channel_filter["channel"] = ch
    return {"status": "ok", "channel": ch}


# ── CHANNEL STATS ─────────────────────────────────────────────────
@app.get("/channel_stats")
def get_channel_stats():
    with engine.lock:
        acc_df = engine.accounts_df.copy()
        tx_df  = engine.transactions_df.copy()

    sus_scores = engine.get_suspicion_scores()
    channels   = ["UPI", "NEFT", "IMPS", "ATM", "Mobile"]
    stats      = {}

    for ch in channels:
        ch_accs = acc_df[acc_df["channel"] == ch] if "channel" in acc_df.columns else acc_df.iloc[:0]
        ids     = set(ch_accs["account_id"].astype(str).tolist())
        fraud_n = int((ch_accs["is_fraud"] == 1).sum()) if "is_fraud" in ch_accs.columns else 0
        sus_n   = sum(1 for a in ids if sus_scores.get(a, 0) >= 0.20)
        stats[ch] = {
            "total":      len(ch_accs),
            "fraud":      fraud_n,
            "suspicious": sus_n,
        }

    vol_matrix = {}
    if "channel" in tx_df.columns:
        for _, row in tx_df.tail(200).iterrows():
            s_id = str(row.get("sender", ""))
            r_id = str(row.get("receiver", ""))
            s_row = acc_df[acc_df["account_id"].astype(str) == s_id]
            r_row = acc_df[acc_df["account_id"].astype(str) == r_id]
            if s_row.empty or r_row.empty:
                continue
            sc  = str(s_row.iloc[0].get("channel", ""))
            rc  = str(r_row.iloc[0].get("channel", ""))
            key = f"{sc}→{rc}"
            vol_matrix[key] = vol_matrix.get(key, 0) + 1

    return {"channels": stats, "volume": vol_matrix}


@app.websocket("/ws/ledger")
async def ws_ledger(websocket: WebSocket):
    await websocket.accept()
    try:
        await pump_ledger(websocket, engine)
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
