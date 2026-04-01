import time
import random
import threading
import pandas as pd
import numpy as np
from datetime import datetime
from collections import deque

from backend.simulation import reset_simulation
from backend.generator import generate_normal_transactions, CHANNELS
from backend.config import (
    MAX_TX_MEMORY, TX_INTERVAL_SEC, TX_STEP_COUNT,
    ATTACK_PREFER_SUS_PCT, ATTACK_POOL_SIZE,
)


class RealTimeEngine:

    def __init__(self):
        self.accounts_df, self.transactions_df = reset_simulation()
        self.lock              = threading.Lock()
        self.banned_accounts   = set()
        self.attack_time       = None
        self.last_attack_name  = None
        self.last_attack_id    = None
        self.last_attack_index = None
        self.attack_counter    = 0
        self._attacking        = False
        self._tx_timestamps    = deque(maxlen=200)
        self._tps              = 0.0
        self._suspicion_scores = {}
        self._acc_counter      = None   # lazily initialized

    # ── New account creation ──────────────────────────────────────
    def create_account(self):
        """
        Add a brand-new account to accounts_df.
        Returns dict with account_id so the caller can pass x/y coords back
        to the frontend (position computed from MD5 hash in the API layer).
        """
        num_devices = 50
        with self.lock:
            if self._acc_counter is None:
                # Start counter after the highest existing numeric suffix
                existing = self.accounts_df["account_id"].tolist()
                nums = []
                for a in existing:
                    try:
                        nums.append(int(str(a).lstrip("A")))
                    except ValueError:
                        pass
                self._acc_counter = max(nums, default=0) + 1
            else:
                self._acc_counter += 1

            acc_id = f"A{str(self._acc_counter).zfill(4)}"

            new_acc = {
                "account_id":    acc_id,
                "creation_time": datetime.now(),
                "device_id":     f"D{str(random.randint(1, num_devices)).zfill(3)}",
                "ip_address":    f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                "balance":       random.randint(5000, 50000),
                "channel":       random.choice(CHANNELS),
                "is_fraud":      0,
                "is_active":     True,
            }
            new_row = pd.DataFrame([new_acc])
            self.accounts_df = pd.concat(
                [self.accounts_df, new_row], ignore_index=True
            )
            # Immediately generate 1 transaction from/to new account to register it
            # This ensures the account appears in the graph feed quickly
            # (done outside lock to avoid deadlock — we pass a copy)
            new_acc_id = acc_id

        # Trigger 1 warm-up transaction involving the new account
        try:
            warm_tx = generate_normal_transactions(self.accounts_df, 1)
            if not warm_tx.empty:
                with self.lock:
                    self.transactions_df = pd.concat(
                        [self.transactions_df, warm_tx], ignore_index=True
                    )
                    if len(self.transactions_df) > MAX_TX_MEMORY:
                        self.transactions_df = self.transactions_df.tail(MAX_TX_MEMORY)
        except Exception:
            pass
        return acc_id

    # ── Normal transactions (generates TX_STEP_COUNT per step) ────
    def step(self):
        if self._attacking:
            return
        new_tx = generate_normal_transactions(self.accounts_df, TX_STEP_COUNT)
        if new_tx.empty:
            return
        with self.lock:
            self.transactions_df = pd.concat(
                [self.transactions_df, new_tx], ignore_index=True
            )
            if len(self.transactions_df) > MAX_TX_MEMORY:
                self.transactions_df = self.transactions_df.tail(MAX_TX_MEMORY)
            now = time.time()
            self._tx_timestamps.append(now)
            recent = [t for t in self._tx_timestamps if now - t <= 10]
            self._tps = len(recent) / 10.0

    # ── Suspicion scoring ─────────────────────────────────────────
    def compute_suspicion_scores(self):
        with self.lock:
            active = self.accounts_df[self.accounts_df["is_active"] == True].copy()
            txns   = self.transactions_df.copy()

        if active.empty or txns.empty:
            self._suspicion_scores = {}
            return {}

        scores       = {}
        device_counts = active["device_id"].value_counts().to_dict()
        now           = datetime.now()
        ages          = []
        tx_counts     = []

        for _, acc in active.iterrows():
            age = (now - pd.Timestamp(acc["creation_time"])).days
            ages.append(age)
            acc_txns = txns[
                (txns["sender"] == acc["account_id"]) |
                (txns["receiver"] == acc["account_id"])
            ]
            tx_counts.append(len(acc_txns))

        median_age = np.median(ages)    if ages      else 365
        mean_tx    = np.mean(tx_counts) if tx_counts else 1
        std_tx     = np.std(tx_counts)  if tx_counts else 1
        std_tx     = std_tx if std_tx > 0 else 1

        for _, acc in active.iterrows():
            acc_id  = acc["account_id"]
            score   = 0.0
            signals = 0

            age = (now - pd.Timestamp(acc["creation_time"])).days
            # New accounts: stronger signal, scaled by how new they are
            if age < median_age * 0.3:
                newness = max(0.0, 1.0 - age / max(median_age * 0.3, 1))
                score += 0.25 + 0.10 * newness   # bonus for brand-new accounts
                signals += 1

            dev_cluster = device_counts.get(acc["device_id"], 1)
            if dev_cluster >= 3:
                score += 0.20 * min(dev_cluster / 10.0, 1.0); signals += 1

            acc_txns = txns[
                (txns["sender"] == acc_id) | (txns["receiver"] == acc_id)
            ]
            tc = len(acc_txns)
            if std_tx > 0 and tc > mean_tx + std_tx:
                score += min((tc - mean_tx) / std_tx * 0.10, 0.25); signals += 1

            in_amt  = acc_txns[acc_txns["receiver"] == acc_id]["amount"].sum()
            out_amt = acc_txns[acc_txns["sender"]   == acc_id]["amount"].sum()
            if in_amt > 0 and (in_amt - out_amt) / in_amt < 0.15:
                score += 0.20; signals += 1

            ch = acc_txns["channel"].nunique() if not acc_txns.empty else 0
            if ch >= 3:
                score += 0.15; signals += 1

            if signals < 2:
                score *= 0.3

            scores[acc_id] = min(round(score, 4), 1.0)

        # Decay: accounts not in current computation lose score over time
        DECAY = 0.018
        for acc_id in list(self._suspicion_scores.keys()):
            if acc_id not in scores:
                decayed = max(0.0, self._suspicion_scores[acc_id] - DECAY)
                if decayed > 0:
                    scores[acc_id] = round(decayed, 4)

        # Smooth blend: 30% new score, 70% previous — prevents jumpy values
        BLEND = 0.30
        for acc_id, new_score in scores.items():
            old = self._suspicion_scores.get(acc_id, 0.0)
            scores[acc_id] = round(old * (1.0 - BLEND) + new_score * BLEND, 4)

        self._suspicion_scores = scores
        return scores

    def get_suspicious_accounts(self, top_pct=0.12):
        scores = self.compute_suspicion_scores()
        if not scores:
            return []
        sorted_accs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        cutoff      = max(1, int(len(sorted_accs) * top_pct))
        return [a for a, s in sorted_accs[:cutoff] if s >= 0.20]

    # ── Smart attack ──────────────────────────────────────────────
    def trigger_attack(self, attack_index: int):
        from backend.attacks import attack_registry
        import random as _random

        self._attacking = True
        try:
            with self.lock:
                active_ids = self.accounts_df[
                    self.accounts_df["is_active"] == True
                ]["account_id"].tolist()

            if len(active_ids) < ATTACK_POOL_SIZE:
                self._attacking = False
                return None, None

            suspicious = [a for a in self.get_suspicious_accounts(top_pct=0.20)
                          if a in active_ids]

            n_sus    = int(ATTACK_POOL_SIZE * ATTACK_PREFER_SUS_PCT)
            n_random = ATTACK_POOL_SIZE - n_sus
            pool     = list(suspicious[:n_sus])
            remaining = [a for a in active_ids if a not in pool]
            pool.extend(_random.sample(remaining, min(n_random, len(remaining))))

            with self.lock:
                self.accounts_df["is_fraud"] = 0
                accounts_copy     = self.accounts_df.copy()
                transactions_copy = self.transactions_df.copy()

            idx = attack_index % len(attack_registry)
            attack_fn = attack_registry[idx]
            upd_acc, upd_tx, attack_name, attack_time = attack_fn(
                accounts_copy, transactions_copy, preferred_ids=pool
            )
            attack_time = pd.Timestamp(attack_time)

            with self.lock:
                self.attack_counter += 1
                self.accounts_df     = upd_acc
                self.transactions_df = upd_tx
                self.attack_time     = attack_time
                self.last_attack_name = attack_name
                self.last_attack_id = f"ATK-{self.attack_counter:03d}"
                self.last_attack_index = idx

        finally:
            self._attacking = False

        return attack_name, attack_time

    # ── Accessors ─────────────────────────────────────────────────
    def get_transactions(self):
        with self.lock:
            return self.transactions_df.tail(150).to_dict(orient="records")

    def get_all_transactions(self):
        with self.lock:
            return self.transactions_df.copy()

    def get_accounts(self):
        with self.lock:
            return self.accounts_df.copy()

    def get_fraud_accounts(self):
        with self.lock:
            if "is_fraud" not in self.accounts_df.columns:
                return []
            return self.accounts_df[
                self.accounts_df["is_fraud"] == 1
            ]["account_id"].tolist()

    def get_active_count(self):
        with self.lock:
            if "is_active" not in self.accounts_df.columns:
                return len(self.accounts_df)
            return int(self.accounts_df["is_active"].sum())

    def get_real_tps(self):
        return round(self._tps, 2)

    def get_suspicion_scores(self):
        return dict(self._suspicion_scores)

    # ── Ban ───────────────────────────────────────────────────────
    def ban_accounts(self, account_ids: list):
        ids = [str(a) for a in account_ids]
        self.banned_accounts.update(ids)
        with self.lock:
            mask = self.accounts_df["account_id"].isin(ids)
            self.accounts_df.loc[mask, "is_active"] = False

    def reset_bans(self):
        self.banned_accounts.clear()
        with self.lock:
            if "is_active" in self.accounts_df.columns:
                self.accounts_df["is_active"] = True

    def reset_state(self):
        with self.lock:
            self.accounts_df, self.transactions_df = reset_simulation()
            self.attack_time       = None
            self.last_attack_name  = None
            self.last_attack_id    = None
            self.last_attack_index = None
            self.attack_counter    = 0
            self._suspicion_scores = {}
            self._tps              = 0.0
            self._acc_counter      = None
        self.banned_accounts.clear()

    def run(self):
        while True:
            self.step()
            time.sleep(TX_INTERVAL_SEC)
