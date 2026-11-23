#!/usr/bin/env python3
"""Example WebProbe extension (API v1, docs/extensions.md).

Adds an `X-Marker: wpx1` header to every request, reports an issue when a
response contains the marker, drops requests whose path starts with
/blocked, and shows counters in its own "Markers" tab.

Run it from Extensions > Installed > Add > "WebProbe extension (process)"
with the command `python3 -I extensions/examples/marker_reflection.py`.
Standard library only.
"""
import base64
import json
import sys

MARKER = b"wpx1"
seen = {"requests": 0, "responses": 0, "reflections": 0, "dropped": 0}


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def add_header(raw, name, value):
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = raw.find(sep)
        if i >= 0:
            nl = sep[: len(sep) // 2]
            return raw[:i] + nl + name + b": " + value + raw[i:]
    return raw


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        kind = msg.get("type")
        if kind == "hello":
            send({
                "type": "register",
                "api": 1,
                "name": "Marker reflection (example)",
                "hooks": ["request", "response"],
                "tab": "Markers",
                "issues": [{
                    "name": "Marker reflected in response",
                    "severity": "info",
                    "description": "The response contains the marker the extension added to the request.",
                    "remediation": "None: this is a demonstration issue.",
                }],
            })
        elif kind == "request":
            seen["requests"] += 1
            if msg.get("path", "").startswith("/blocked"):
                seen["dropped"] += 1
                send({"id": msg["id"], "action": "drop"})
                continue
            raw = add_header(base64.b64decode(msg["raw"]), b"X-Marker", MARKER)
            send({"id": msg["id"], "action": "continue", "raw": base64.b64encode(raw).decode()})
        elif kind == "response":
            seen["responses"] += 1
            raw = base64.b64decode(msg["raw"])
            reply = {"id": msg["id"], "action": "continue"}
            if MARKER in raw:
                seen["reflections"] += 1
                reply["issues"] = [{
                    "name": "Marker reflected in response",
                    "severity": "info",
                    "confidence": "Firm",
                    "detail": "The response body contains %s." % MARKER.decode(),
                }]
            send(reply)
        elif kind == "tab":
            text = "\n".join("%s: %d" % (k.replace("requests", "requests seen"), v) for k, v in seen.items())
            send({"id": msg["id"], "text": text})
        elif "id" in msg:
            send({"id": msg["id"], "action": "continue"})


if __name__ == "__main__":
    main()
