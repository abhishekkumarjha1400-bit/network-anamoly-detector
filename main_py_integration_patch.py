# ═══════════════════════════════════════════════════════════════
# HOW TO WIRE behavior_profiler.py INTO YOUR EXISTING main.py
# ═══════════════════════════════════════════════════════════════
#
# Make exactly 4 changes in main.py — nothing else needs to touch.
#
# ───────────────────────────────────────────────────────────────
# CHANGE 1 — Add import at the top of main.py (with your other imports)
# ───────────────────────────────────────────────────────────────

from behavior_profiler import BehaviorProfiler

# ───────────────────────────────────────────────────────────────
# CHANGE 2 — Instantiate in App.__init__(), right after your
#             other model lines (around line 106):
# ───────────────────────────────────────────────────────────────

#  BEFORE (existing code):
self.if_model  = IsolationForestModel()
self.ai_engine = AIThreatEngine()

#  AFTER (add one line):
self.if_model   = IsolationForestModel()
self.ai_engine  = AIThreatEngine()
self.profiler   = BehaviorProfiler()       # ← add this

# ───────────────────────────────────────────────────────────────
# CHANGE 3 — Call it inside _on_packet(), right after your
#             existing model calls (around line 612):
# ───────────────────────────────────────────────────────────────

#  BEFORE (existing code):
is_if, if_score = self.if_model.update(vector)
is_ai, ai_type, severity = self.ai_engine.analyze(features)
is_anomaly = is_if or is_ai

#  AFTER (add 3 lines):
is_if, if_score  = self.if_model.update(vector)
is_ai, ai_type, severity = self.ai_engine.analyze(features)

bp_score, bp_reasons = self.profiler.update(features)   # ← new
bp_severity = self.profiler.get_severity(bp_score)      # ← new
is_bp = bp_score >= BehaviorProfiler.THRESHOLD_MEDIUM   # ← new

is_anomaly = is_if or is_ai or is_bp                    # ← update this line

# Log behavioural anomalies:
if is_bp:
    log_anomaly(features, f"BEHAVIOR:{bp_severity}", bp_score)

# ───────────────────────────────────────────────────────────────
# CHANGE 4 — Show behavioural hits in the threat_box (optional
#             but recommended). Find where is_ai is logged in
#             _add_row() (~line 800) and add below it:
# ───────────────────────────────────────────────────────────────

#  After the existing "if is_ai:" block, add:
if is_bp and bp_reasons:
    now = datetime.now().strftime("%H:%M:%S")
    msg = (f"[{now}] BEHAVIOR {bp_severity}\n"
           f"  Score: {bp_score:.3f}\n"
           + "\n".join(f"  • {r}" for r in bp_reasons)
           + f"\n{'─' * 28}\n")
    self.threat_box.config(state="normal")
    self.threat_box.insert("1.0", msg)
    self.threat_box.config(state="disabled")

# ═══════════════════════════════════════════════════════════════
# THAT'S IT. No other changes needed.
# The profiler auto-saves to ip_profiles.json every 60 seconds.
# On restart it reloads all learned baselines automatically.
# ═══════════════════════════════════════════════════════════════
