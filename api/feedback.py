"""
Feedback endpoint — NPS + free-text after every signed cert.
Mount at /feedback on meok-attestation-api.

POST /feedback
{
  "cert_id": "MEOK-EUAIAC-A1B2C3D4",
  "score": 8,           # 0-10 NPS
  "feedback": "Worked great but I wish it...",
  "email": "user@example.com" # optional
}

Stores to ~/.hermes/feedback.jsonl (append-only)
"""
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path


FEEDBACK_LOG = Path("/tmp/meok-feedback.jsonl")


class handler(BaseHTTPRequestHandler):
    def _json(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_OPTIONS(self):
        self._json(204, {})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            data = json.loads(body) if body else {}
        except Exception:
            return self._json(400, {"error": "Invalid JSON"})

        cert_id = data.get("cert_id", "").strip()
        score = data.get("score")
        feedback = (data.get("feedback") or "")[:5000].strip()
        email = (data.get("email") or "").strip()

        if not isinstance(score, (int, float)) or not (0 <= score <= 10):
            return self._json(400, {
                "error": "score must be a number 0-10",
            })

        entry = {
            "received_utc": datetime.now(timezone.utc).isoformat(),
            "cert_id": cert_id,
            "score": int(score),
            "category": (
                "promoter" if score >= 9 else
                "passive" if score >= 7 else
                "detractor"
            ),
            "feedback": feedback,
            "email": email,
        }

        # Append to log
        try:
            with open(FEEDBACK_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            return self._json(500, {"error": f"Storage failed: {e}"})

        # Trigger follow-up for high-NPS (promoter) entries with email
        followup = None
        if entry["category"] == "promoter" and email:
            followup = (
                "Thank you — promoters help MEOK grow. "
                "You'll get a follow-up email asking if we can quote your feedback (anonymous or attributed, your call)."
            )

        return self._json(200, {
            "status": "recorded",
            "thank_you": "Your feedback shapes the roadmap. Reads every entry: Nick (hello@meok.ai).",
            "category": entry["category"],
            "followup": followup,
        })

    def do_GET(self):
        # Public NPS summary (no PII)
        if not FEEDBACK_LOG.exists():
            return self._json(200, {
                "total_responses": 0,
                "note": "No feedback yet. POST {cert_id, score 0-10, feedback?, email?}",
            })
        promoters, passives, detractors = 0, 0, 0
        try:
            with open(FEEDBACK_LOG) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                        cat = e.get("category", "")
                        if cat == "promoter":
                            promoters += 1
                        elif cat == "passive":
                            passives += 1
                        else:
                            detractors += 1
                    except Exception:
                        continue
        except Exception:
            pass
        total = promoters + passives + detractors
        if total == 0:
            return self._json(200, {"total_responses": 0})
        nps = round(100 * (promoters - detractors) / total, 1)
        return self._json(200, {
            "total_responses": total,
            "nps_score": nps,
            "promoters": promoters,
            "passives": passives,
            "detractors": detractors,
            "interpretation": (
                "Excellent" if nps >= 50 else
                "Good" if nps >= 30 else
                "Needs work"
            ),
        })
