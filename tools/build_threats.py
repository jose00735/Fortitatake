#!/usr/bin/env python3
"""Build and check the threat packs (content/threats/*.yaml) into web/content/threats.json.

Checks, per the pack format in content/threats/README.md:
- every pack has the required fields, unique signature ids and valid regexes;
- every generator variant trips at least one of its own pack's signatures;
- no normal office request (the shapes the five traffic generators send) trips any signature;
- generator requests aim only at {{target_host}} (no other Host, no absolute URL to elsewhere).

The matcher here mirrors the one in the FortiTatake OS agent (ftkos/agent/ips.go) and the
simulator (web/js/labs/ips.js): same buffers, same literal and regex semantics.
Usage: python3 tools/build_threats.py [--check]
"""
import glob
import json
import os
import re
import sys
import urllib.parse

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEVERITIES = ["info", "low", "medium", "high", "critical"]
BUFS = {"method", "uri", "header", "body", "raw"}


def fill(tpl, target="web.lab", sinkhole="198.51.100.250", token="ftk-0000"):
    t = tpl.replace("{{target_host}}", target).replace("{{sinkhole}}", sinkhole).replace("{{token}}", token)
    lines = t.split("\n")
    out = "\r\n".join(lines)
    if "\r\n\r\n" not in out:
        out += "\r\n\r\n"
    return out


def buffers(payload):
    """The HTTP view of one request payload (str)."""
    head, _, body = payload.partition("\r\n\r\n")
    lines = head.split("\r\n")
    first = lines[0].split(" ")
    method = first[0] if first else ""
    target = first[1] if len(first) > 1 else ""
    uri = urllib.parse.unquote(target)
    return {"method": method, "uri": uri, "header": "\r\n".join(lines[1:]), "body": body, "raw": payload}


def cond_ok(c, bufs):
    b = bufs.get(c["buf"], "")
    if "hex" in c:
        return bytes.fromhex(c["hex"]).decode("latin-1") in b
    if "contains" in c:
        if c.get("nocase"):
            return c["contains"].lower() in b.lower()
        return c["contains"] in b
    return re.search(c["regex"], b, re.I if c.get("nocase") else 0) is not None


def matches(sig, payload, port=None):
    if port is not None and sig.get("ports") and port not in sig["ports"]:
        return False
    bufs = buffers(payload)
    return all(cond_ok(c, bufs) for c in sig["match"])


# what the office generators send (ftkos/agent/gen.go), plus ordinary admin and API traffic
NORMAL = [
    "GET / HTTP/1.1\nHost: www.google.com\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\nAccept-Language: es-CO,es;q=0.9,en;q=0.8\nAccept-Encoding: identity\nConnection: keep-alive",
    "GET /api/v1/news HTTP/1.1\nHost: www.eltiempo.com\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0\nConnection: keep-alive",
    "GET /api/v1/calendar/events?days=7 HTTP/1.1\nHost: app.office-saas.lab\nUser-Agent: OfficeSync/4.2\nAuthorization: Bearer lab-token\nAccept: application/json\nConnection: close",
    "GET /api/v2/monitor/system/status HTTP/1.1\nHost: 10.10.10.1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0\nCookie: APSCOOKIE_123=abc\nConnection: keep-alive",
    "PUT /api/v2/cmdb/system/admin/backup-admin HTTP/1.1\nHost: 10.10.10.1\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0\nAuthorization: Bearer 0123456789\nContent-Type: application/json\n\n{\"accprofile\": \"prof_admin\"}",
    "GET /api/v1/totp/user-backup-code HTTP/1.1\nHost: vpn.lab\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0",
    "GET /license/keys-status HTTP/1.1\nHost: vpn.lab\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0",
    "POST /login HTTP/1.1\nHost: citas.clinicasanrafael.co\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0\nContent-Type: application/x-www-form-urlencoded\n\nuser=maria&pass=%24%7Bsecret%7D",
    "GET /search?q=%24%7Bnombre%7D+java+naming HTTP/1.1\nHost: www.google.com\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0",
    "GET /docs/jndi-lookup.html HTTP/1.1\nHost: logging.apache.org\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0\nForwarded: for=192.0.2.60;proto=https",
    "GET /remote/login?lang=en HTTP/1.1\nHost: vpn.clinica.lab\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0",
    "GET /remote/fgt_lang?lang=es HTTP/1.1\nHost: vpn.clinica.lab\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0",
    "POST /api/v2.0/cmdb/system/admin HTTP/1.1\nHost: waf.lab\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0\nAuthorization: eyJ1c2VybmFtZSI6ImFkbWluIn0=\nContent-Type: application/json\n\n{\"data\": {\"name\": \"ops\"}}",
    "GET /_layouts/15/ToolPane.aspx?DisplayMode=Edit HTTP/1.1\nHost: intranet.lab\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0\nReferer: https://intranet.lab/sites/rrhh/SitePages/Home.aspx",
    "GET /_layouts/15/SignOut.aspx HTTP/1.1\nHost: intranet.lab\nUser-Agent: Mozilla/5.0 Chrome/130.0.0.0",
]
# binary requests the office generators send: SMB2 negotiate and a read (gen.go)
NORMAL_HEX = [
    "000000a8fe534d4240000100000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000024000200010000007f000000000000000000000000000000000000000000000000000000000002021002",
    "00000050fe534d424000010000000000080001000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000436f6e746162696c696461645c62616c616e63652e786c73780036353533360000",
]


def main():
    check_only = "--check" in sys.argv
    packs, errors, sig_ids = [], [], {}
    for path in sorted(glob.glob(os.path.join(ROOT, "content", "threats", "TP-*.yaml"))):
        name = os.path.basename(path)
        p = yaml.safe_load(open(path, encoding="utf-8"))
        for k in ("id", "cve", "name", "severity", "target", "location", "summary", "signatures", "generator", "lesson"):
            if k not in p:
                errors.append(f"{name}: missing {k}")
        if p.get("severity") not in SEVERITIES:
            errors.append(f"{name}: severity must be one of {SEVERITIES}")
        if not re.fullmatch(r"TP-\d{4}-\d+", str(p.get("id", ""))):
            errors.append(f"{name}: id must look like TP-2021-44228")
        if not re.fullmatch(r"[A-Za-z0-9]+(\.[A-Za-z0-9]+)+", str(p.get("name", ""))):
            errors.append(f"{name}: name must be dotted words")
        for s in p.get("signatures", []):
            if s.get("id") in sig_ids:
                errors.append(f"{name}: signature id {s.get('id')} also in {sig_ids[s.get('id')]}")
            sig_ids[s.get("id")] = name
            s.setdefault("proto", "tcp")
            for c in s.get("match", []):
                if c.get("buf") not in BUFS:
                    errors.append(f"{name}/{s.get('id')}: bad buffer {c.get('buf')}")
                if sum(k in c for k in ("contains", "regex", "hex")) != 1:
                    errors.append(f"{name}/{s.get('id')}: each condition has exactly one of contains, regex or hex")
                if "hex" in c:
                    try:
                        bytes.fromhex(c["hex"])
                    except ValueError:
                        errors.append(f"{name}/{s.get('id')}: bad hex")
                if "regex" in c:
                    try:
                        re.compile(c["regex"])
                    except re.error as e:
                        errors.append(f"{name}/{s.get('id')}: bad regex: {e}")
                    if c["regex"].startswith("(?"):
                        errors.append(f"{name}/{s.get('id')}: use nocase: true, not inline flags (the browser can't read them)")
        gen = p.get("generator", {})
        port = gen.get("port", 80)
        for v in gen.get("variants", []):
            if "request_hex" in v:  # a binary protocol: no Host header to check
                req = bytes.fromhex(v["request_hex"]).decode("latin-1")
                if not any(matches(s, req, port) for s in p.get("signatures", [])):
                    errors.append(f"{name}/{v['name']}: trips none of its signatures")
                continue
            req = fill(v["request"])
            host = re.search(r"\r\nHost: ([^\r]*)", req)
            if not host or host.group(1) != "web.lab":
                errors.append(f"{name}/{v['name']}: Host must be {{{{target_host}}}}")
            if re.match(r"[A-Z]+ https?://", req):
                errors.append(f"{name}/{v['name']}: absolute URLs are not allowed")
            if not any(matches(s, req, port) for s in p.get("signatures", [])):
                errors.append(f"{name}/{v['name']}: trips none of its signatures")
        packs.append(p)
    for i, n in enumerate(NORMAL + NORMAL_HEX):
        req = bytes.fromhex(n).decode("latin-1") if i >= len(NORMAL) else fill(n)
        for p in packs:
            for s in p["signatures"]:
                if matches(s, req):
                    errors.append(f"{p['id']}/{s['id']} trips on normal request {i + 1}: {n.splitlines()[0]}")
    # attack sequences (content/sequences): the Range and the capstones run them
    seqs = []
    pack_ids = {p["id"] for p in packs}
    kinds = {"connect", "attack", "proc", "cpu", "files", "logins"}
    for path in sorted(glob.glob(os.path.join(ROOT, "content", "sequences", "S*.yaml"))):
        name = os.path.basename(path)
        q = yaml.safe_load(open(path, encoding="utf-8"))
        for k in ("id", "name", "environment", "summary", "steps"):
            if k not in q:
                errors.append(f"{name}: missing {k}")
        ids = set()
        for st in q.get("steps", []):
            sid = st.get("id")
            if sid in ids:
                errors.append(f"{name}: duplicate step {sid}")
            ids.add(sid)
            for k in ("id", "title", "tactic", "attack", "do", "controls"):
                if k not in st:
                    errors.append(f"{name}/{sid}: missing {k}")
            do = st.get("do") or {}
            if len(do) != 1 or next(iter(do)) not in kinds:
                errors.append(f"{name}/{sid}: do must be one of {sorted(kinds)}")
                continue
            kind, a = next(iter(do.items()))
            if kind == "attack" and a.get("pack") not in pack_ids:
                errors.append(f"{name}/{sid}: unknown pack {a.get('pack')}")
            to = str(a.get("to", ""))
            if re.fullmatch(r"(c2|url|phish):\d+", to) and int(to.split(":")[1]) > 5:
                errors.append(f"{name}/{sid}: feed pick {to} is out of range (0-5)")
        seqs.append(q)
    if errors:
        print("\n".join(errors))
        sys.exit(1)
    nsig = sum(len(p["signatures"]) for p in packs)
    nvar = sum(len(p["generator"]["variants"]) for p in packs)
    print(f"sequences: {len(seqs)} ({sum(len(q['steps']) for q in seqs)} steps)")
    print(f"threats: {len(packs)} packs, {nsig} signatures, {nvar} attack variants; {len(NORMAL) + len(NORMAL_HEX)} normal requests stay quiet")
    if not check_only:
        out = os.path.join(ROOT, "web", "content", "threats.json")
        json.dump({"packs": packs, "sequences": seqs}, open(out, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))


if __name__ == "__main__":
    main()
