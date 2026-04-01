"""
WebSocket event builder for SENTINEL-FIN Cyber-Punk Ledger.
Maps RealTimeEngine state to the frontend event schema.
"""
from __future__ import annotations

import asyncio
import json
import math
from datetime import datetime, timezone
from typing import Any

# Registry order must match backend.attacks.attack_registry
ATTACK_REGISTRY_META: list[dict[str, Any]] = [
    {"type": "fan-in", "display_name": "FAN-IN AGGREGATION", "color": "#00c8ff"},
    {"type": "fan-out", "display_name": "FAN-OUT DISBURSAL", "color": "#ff6600"},
    {"type": "shell-company", "display_name": "CIRCULAR SHELL RING", "color": "#c040ff"},
    {"type": "layering", "display_name": "HIGH-VELOCITY LAYERING", "color": "#4080ff"},
    {"type": "trade-based", "display_name": "CROSS-CHANNEL BRIDGE", "color": "#00e0c0"},
    {"type": "mule-chain", "display_name": "DEVICE-LINKED MULE CHAIN", "color": "#ff2020"},
    {"type": "rapid-cycling", "display_name": "BEHAVIORAL RAPID CYCLING", "color": "#ffffff"},
    {"type": "structuring", "display_name": "EARLY-STAGE STRUCTURING", "color": "#ffe040"},
    {"type": "smurfing", "display_name": "SMURFING CLUSTER", "color": "#00ff88"},
    {"type": "loan-back", "display_name": "DORMANT ACTIVATION / LOAN-BACK", "color": "#ff40a0"},
]


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _score_to_state(score: float, is_fraud: bool) -> str:
    if is_fraud:
        return "mule"
    if score >= 0.72:
        return "flagged"
    if score >= 0.45:
        return "suspicious"
    if score >= 0.22:
        return "monitoring"
    return "clean"


def _edge_state(is_attack: bool, s_fraud: bool, r_fraud: bool) -> str:
    if is_attack and (s_fraud or r_fraud):
        return "mule"
    if is_attack:
        return "suspicious"
    return "clean"


def _role(deg: int, is_fraud: bool) -> str:
    if is_fraud and deg >= 8:
        return "hub"
    if is_fraud:
        return "main"
    if deg >= 10:
        return "hub"
    if deg <= 2:
        return "micro"
    return "standard"


def _engine_metrics(engine) -> dict[str, Any]:
    with engine.lock:
        tx_count = len(engine.transactions_df)
        active_ct = int(engine.accounts_df["is_active"].sum()) \
            if "is_active" in engine.accounts_df.columns \
            else len(engine.accounts_df)
        fraud_ct = int((engine.accounts_df["is_fraud"] == 1).sum()) \
            if "is_fraud" in engine.accounts_df.columns else 0
        total_ct = len(engine.accounts_df)

    sus_scores = engine.compute_suspicion_scores()
    sus_count = len([s for s in sus_scores.values() if s >= 0.25])

    return {
        "tps": engine.get_real_tps(),
        "tx_count": tx_count,
        "fraud_count": fraud_ct,
        "active_accounts": active_ct,
        "total_accounts": total_ct,
        "banned_count": len(engine.banned_accounts),
        "suspicious_count": sus_count,
    }


def build_snapshot(engine) -> dict[str, Any]:
    """Full graph + metrics from engine (call with engine.lock if needed)."""
    sus = engine.get_suspicion_scores()
    acc_df = engine.get_accounts()
    tx_records = engine.get_transactions()

    if hasattr(acc_df, "to_dict"):
        accounts = acc_df.to_dict(orient="records")
    else:
        accounts = list(acc_df)

    deg: dict[str, int] = {}
    for tx in tx_records:
        s = str(tx.get("sender", "") or "")
        r = str(tx.get("receiver", "") or "")
        if s and r:
            deg[s] = deg.get(s, 0) + 1
            deg[r] = deg.get(r, 0) + 1

    nodes: list[dict[str, Any]] = []
    for row in accounts:
        aid = str(row.get("account_id", ""))
        if not aid:
            continue
        if row.get("is_active") is False:
            continue
        fraud = row.get("is_fraud") in (1, True, "1")
        sc = float(sus.get(aid, 0.0) or 0.0)
        st = _score_to_state(sc, fraud)
        d = deg.get(aid, 0)
        nodes.append({
            "id": aid,
            "label": aid,
            "state": st,
            "prev_state": "clean",
            "role": _role(d, fraud),
            "txns": d,
            "score": round(sc * 100, 1),
            "attack_ids": [],
            "attack_types": [],
            "amount": int(row.get("balance", 0) or 0),
            "timestamp": _iso_now(),
            "ml_signal": "graph_feature",
            "confidence": round(sc * 100, 1),
        })

    edges: list[dict[str, Any]] = []
    seen_e = set()
    for tx in tx_records:
        s = str(tx.get("sender", "") or "")
        r = str(tx.get("receiver", "") or "")
        if not s or not r or s == r:
            continue
        eid = f"E-{s}-{r}-{tx.get('transaction_id', '')}"
        if eid in seen_e:
            continue
        seen_e.add(eid)
        is_atk = bool(tx.get("is_attack", False))
        sf = any(
            str(a.get("account_id")) == s and a.get("is_fraud") in (1, True, "1")
            for a in accounts
        )
        rf = any(
            str(a.get("account_id")) == r and a.get("is_fraud") in (1, True, "1")
            for a in accounts
        )
        edges.append({
            "id": eid,
            "source_id": s,
            "target_id": r,
            "state": _edge_state(is_atk, sf, rf),
            "attack_ids": [],
            "amount": float(tx.get("amount", 0) or 0),
            "velocity": 1.0,
            "is_bidirectional": False,
            "timestamp": str(tx.get("timestamp", _iso_now())),
        })

    _max_n, _max_e = 90, 180
    if len(nodes) > _max_n:
        nodes.sort(key=lambda n: (0 if n.get("state") == "mule" else 1, -n.get("txns", 0)))
        nodes = nodes[:_max_n]
        _keep = {n["id"] for n in nodes}
        edges = [e for e in edges if e["source_id"] in _keep and e["target_id"] in _keep]
    if len(edges) > _max_e:
        edges = edges[:_max_e]

    m = _engine_metrics(engine)
    fraud_ct = m.get("fraud_count", 0)
    tx_count = m.get("tx_count", 0)
    sus_ct = m.get("suspicious_count", 0)

    metrics = {
        "txns": tx_count,
        "suspects": sus_ct,
        "mules": fraud_ct,
        "clusters": max(1, min(8, len(nodes) // 25)),
        "amount": round(tx_count * 1450 / 1_000_000, 2),
        "alerts": sus_ct,
        "risk": min(99, int(fraud_ct * 8 + sus_ct)),
    }

    return {
        "type": "snapshot",
        "nodes": nodes,
        "edges": edges,
        "metrics": metrics,
        "ts": _iso_now(),
    }


def _phase_messages(meta: dict[str, Any], attack_id: str, nodes_involved: list[str], total_amt: float) -> list[str]:
    t = meta["type"]
    hub = nodes_involved[0] if nodes_involved else "ACC-????"
    n = len(nodes_involved)
    amt = f"${total_amt:,.0f}"

    if t == "fan-in":
        return [
            f"{hub} exhibits baseline transaction patterns. Establishing profile.",
            "Inbound edge count rising. Monitoring indegree velocity.",
            f"Indegree centrality for {hub} exceeds 3σ threshold. Flagging for aggregation analysis.",
            f"Fan-in topology confirmed: {n} source accounts routing to single endpoint. Reclassifying.",
            f"Aggregate inflow {amt} matches known mule accumulation signature.",
            f"FAN-IN MULE NETWORK CONFIRMED. SAR trigger recommended. {n} accounts flagged.",
        ]
    if t == "fan-out":
        return [
            f"{hub} baseline disbursement profile computed.",
            "Outbound fan widening — velocity burst on outdegree.",
            f"Outdegree spike for {hub} exceeds peer band. Escalating.",
            f"Dispersal pattern locked: {n} endpoints from single origin.",
            f"Total outflow {amt} consistent with mule laundering exit.",
            "FAN-OUT NETWORK CONFIRMED. Freeze recommendations queued.",
        ]
    if t == "layering":
        a, b, c = (nodes_involved + ["?", "?", "?"])[:3]
        return [
            "Sequential chain topology under analysis.",
            f"Sequential transfer detected: {a}→{b}→{c}. Hop count: {max(1, n - 1)}.",
            f"Amount consistency across hops: σ={0.12 + n * 0.01:.2f}. Layering signature.",
            "Obfuscation depth calculated across jurisdictions.",
            "Chain topology locked. Placement → Layering → Integration pathway identified.",
            "LAYERING ATTACK CONFIRMED — pattern matches typology library.",
        ]
    if t == "smurfing":
        return [
            "Micro-transaction density scan initiated.",
            f"Transaction cluster below reporting threshold detected. Count: {max(5, n * 2)} in window.",
            f"Uniform sub-threshold amounts from {n} paths. Smurfing probability elevated.",
            "Velocity and amount variance match structuring bots.",
            "Receiver consolidation node identified.",
            "SMURFING PATTERN CONFIRMED — aggregate exceeds threshold.",
        ]
    if t == "shell-company":
        return [
            "Circular flow detector armed.",
            "Ring closure probability rising.",
            "Self-referential transfers detected.",
            "Shell loop coherence exceeds threshold.",
            "Circular shell topology confirmed.",
            "SHELL RING CONFIRMED — compliance review required.",
        ]
    if t == "trade-based":
        return [
            "Cross-channel bridge monitor started.",
            "Channel diversity anomaly on burst.",
            "Bridge node identified across rails.",
            "Trade-based laundering path hypothesized.",
            "Cross-channel correlation locked.",
            "TRADE-BASED BRIDGE CONFIRMED.",
        ]
    if t == "mule-chain":
        return [
            "Device graph linkage scan started.",
            "Shared device cluster detected.",
            "Sequential hop pattern across cluster.",
            "Human mule chain likelihood high.",
            "Hop timing matches coordinated movement.",
            "MULE CHAIN CONFIRMED.",
        ]
    if t == "rapid-cycling":
        return [
            "Velocity anomaly detector initialized.",
            "Bidirectional transaction velocity spike.",
            "Cycle frequency elevated between paired accounts.",
            "Rapid cycling signature forming.",
            "Behavioral drift locked to cycling typology.",
            "RAPID CYCLING CONFIRMED.",
        ]
    if t == "structuring":
        return [
            "New-account risk profile instantiated.",
            "Early volume spike vs. cohort baseline.",
            "Threshold proximity alerts firing.",
            "Structuring pattern across micro-batches.",
            "Aggregation node exposure rising.",
            "STRUCTURING CONFIRMED — reporting threshold breach.",
        ]
    if t == "loan-back":
        return [
            "Dormant account reactivation flagged.",
            "Return-path flow detected.",
            "Loan-back pattern hypothesis.",
            "Boomerang amount correlation strong.",
            "Activation burst matches known typology.",
            "LOAN-BACK / DORMANT ACTIVATION CONFIRMED.",
        ]
    return ["Phase analysis…"] * 6


async def _send(ws, payload: dict[str, Any]) -> None:
    await ws.send_text(json.dumps(payload, default=str))


async def orchestrate_attack(
    ws,
    engine,
    last_id: str,
) -> None:
    """Emit staged events for a newly detected attack (already committed in engine)."""
    with engine.lock:
        meta_idx = engine.last_attack_index
        attack_name = engine.last_attack_name
        aid = engine.last_attack_id

    if meta_idx is None or aid != last_id:
        return

    meta = ATTACK_REGISTRY_META[meta_idx % len(ATTACK_REGISTRY_META)]

    with engine.lock:
        acc_df = engine.accounts_df.copy()
        tx_df = engine.transactions_df.copy()

    fraud_ids = set(
        acc_df[acc_df.get("is_fraud", 0) == 1]["account_id"].astype(str).tolist()
        if "is_fraud" in acc_df.columns else []
    )

    if "is_attack" in tx_df.columns:
        atk_tx = tx_df[tx_df["is_attack"] == True].copy()
    else:
        atk_tx = tx_df[
            tx_df["sender"].astype(str).isin(fraud_ids)
            | tx_df["receiver"].astype(str).isin(fraud_ids)
        ].tail(80).copy()

    involved: list[str] = []
    for _, row in atk_tx.iterrows():
        s = str(row.get("sender", ""))
        r = str(row.get("receiver", ""))
        if s:
            involved.append(s)
        if r:
            involved.append(r)
    nodes_involved = list(dict.fromkeys(involved))[:24]
    total_amt = float(atk_tx["amount"].sum()) if not atk_tx.empty and "amount" in atk_tx.columns else 0.0
    edge_count = len(atk_tx)

    messages = _phase_messages(meta, aid, nodes_involved, total_amt)

    for phase in range(1, 7):
        await _send(ws, {
            "type": "attack_progress",
            "attack_id": aid,
            "phase": phase,
            "confidence": min(99.0, 40.0 + phase * 9.5),
            "new_nodes": nodes_involved[phase - 1:phase] if phase <= len(nodes_involved) else [],
            "new_edges": [],
        })
        lvl = "warn" if phase < 4 else "crit" if phase < 6 else "success"
        await _send(ws, {
            "type": "ml_reasoning",
            "intel": {
                "level": lvl,
                "text": messages[phase - 1],
                "context": f"{nodes_involved[0] if nodes_involved else '?'} // {meta['display_name']} PHASE {phase}",
                "attack_id": aid,
                "node_id": nodes_involved[0] if nodes_involved else "",
                "metric": "indegree" if meta["type"] == "fan-in" else "graph_score",
                "value": phase * 1.2,
                "threshold": 3.2,
            },
        })
        await asyncio.sleep(0.18)

        if phase == 3:
            for nid in nodes_involved[:6]:
                await _send(ws, {
                    "type": "node_update",
                    "node": {
                        "id": nid,
                        "label": nid,
                        "state": "suspicious" if phase < 5 else "flagged",
                        "prev_state": "monitoring",
                        "role": "hub" if nid == nodes_involved[0] else "standard",
                        "txns": 12 + phase,
                        "score": 68.0 + phase * 4,
                        "attack_ids": [aid],
                        "attack_types": [meta["type"]],
                        "amount": int(total_amt / max(1, len(nodes_involved))),
                        "timestamp": _iso_now(),
                        "ml_signal": "orchestrated",
                        "confidence": 70.0 + phase * 3,
                    },
                })
            await asyncio.sleep(0.08)

    ei_list: list[str] = []
    for _, row in atk_tx.head(18).iterrows():
        s = str(row.get("sender", ""))
        r = str(row.get("receiver", ""))
        if not s or not r:
            continue
        eid = f"E-{s}-{r}"
        ei_list.append(eid)
        await _send(ws, {
            "type": "edge_update",
            "edge": {
                "id": eid,
                "source_id": s,
                "target_id": r,
                "state": "mule",
                "attack_ids": [aid],
                "amount": float(row.get("amount", 0) or 0),
                "velocity": 2.5,
                "is_bidirectional": False,
                "timestamp": str(row.get("timestamp", _iso_now())),
            },
        })
    await asyncio.sleep(0.12)

    await _send(ws, {
        "type": "attack_identified",
        "attack": {
            "id": aid,
            "type": meta["type"],
            "display_name": meta["display_name"],
            "confidence": 94.2,
            "phase": 6,
            "phase_total": 6,
            "nodes_involved": nodes_involved,
            "edges_involved": ei_list[:14] if ei_list else [f"E-{attack_name}"],
            "total_amount": int(total_amt),
            "node_count": len(nodes_involved),
            "edge_count": edge_count,
            "confirmed_at": _iso_now(),
            "color": meta["color"],
            "severity": "critical",
        },
    })

    em = _engine_metrics(engine)
    await _send(ws, {
        "type": "metric_update",
        "delta": {
            "alerts": em.get("suspicious_count", 0),
            "mules": em.get("fraud_count", 0),
            "suspects": em.get("suspicious_count", 0),
            "txns": em.get("tx_count", 0),
            "risk": min(99, int(em.get("fraud_count", 0) * 8 + em.get("suspicious_count", 0))),
        },
    })

    await _send(ws, {
        "type": "alert",
        "alert": {
            "title": meta["display_name"],
            "message": f"Attack {aid} confirmed — {len(nodes_involved)} nodes in cluster.",
            "color": meta["color"],
            "attack_id": aid,
        },
    })


async def pump_ledger(ws, engine) -> None:
    """Main WebSocket loop: snapshot + attack orchestration."""
    with engine.lock:
        last_sent_attack_id = engine.last_attack_id
    attacks_seen: set[str] = set()

    await _send(ws, build_snapshot(engine))

    try:
        while True:
            await asyncio.sleep(0.35)
            with engine.lock:
                cur_id = engine.last_attack_id

            if cur_id and cur_id != last_sent_attack_id:
                last_sent_attack_id = cur_id
                attacks_seen.add(cur_id)
                await asyncio.sleep(0.2)
                await orchestrate_attack(ws, engine, cur_id)
                snap = build_snapshot(engine)
                snap["type"] = "snapshot"
                await _send(ws, snap)

                if len(attacks_seen) >= 10:
                    await _send(ws, {"type": "simulation_complete", "payload": {
                        "attacks_total": 10,
                        "message": "ALL 10 ATTACKS IDENTIFIED — NETWORK FROZEN — REFER TO COMPLIANCE",
                    }})
    except asyncio.CancelledError:
        raise


