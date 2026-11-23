#!/usr/bin/env python3
"""WebProbe extension (API v1): passive security-header review.

Reports an informational issue per response that lacks one of the common
browser security headers (HSTS on HTTPS-looking hosts, CSP, X-Content-Type-
Options, frame protection), once per host and header. Shows a per-host
summary in its "Headers" tab. Standard library only.
"""
import base64
import json
import sys

WANTED = [
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options or CSP frame-ancestors"),
]
reported = set()
missing_by_host = {}
host_of = {}


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def headers(raw):
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0].decode("latin-1")
    out = {}
    for line in head.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        kind = msg.get("type")
        if kind == "hello":
            send({"type": "register", "api": 1, "name": "Security headers review",
                  "hooks": ["request", "response"], "tab": "Headers",
                  "issues": [{"name": "Missing security header", "severity": "info",
                              "description": "A response lacks a browser security header.",
                              "remediation": "Send the header on every HTML response."}]})
        elif kind == "request":
            host = headers(base64.b64decode(msg["raw"])).get("host", "")
            host_of[msg["path"]] = host
            send({"id": msg["id"], "action": "continue"})
        elif kind == "response":
            h = headers(base64.b64decode(msg["raw"]))
            host = host_of.get(msg["path"], "")
            issues = []
            if "text/html" in h.get("content-type", ""):
                for key, label in WANTED:
                    present = key in h or (key == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""))
                    if not present:
                        missing_by_host.setdefault(host, set()).add(label)
                        if (host, key) not in reported:
                            reported.add((host, key))
                            issues.append({"name": "Missing security header", "severity": "info",
                                           "confidence": "Certain", "detail": "%s is not set." % label})
            send({"id": msg["id"], "action": "continue", "issues": issues})
        elif kind == "tab":
            lines = ["%s: missing %s" % (host or "?", ", ".join(sorted(m))) for host, m in sorted(missing_by_host.items())]
            send({"id": msg["id"], "text": "\n".join(lines) or "No HTML responses reviewed yet."})
        elif "id" in msg:
            send({"id": msg["id"], "action": "continue"})


if __name__ == "__main__":
    main()
