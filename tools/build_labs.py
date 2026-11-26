#!/usr/bin/env python3
"""Build web/content/labs.json from content/labs/*.yaml (lab packs) and lint them.

A lab file holds one lab. Topologies can come from content/labs/_templates.yaml:
  topology: {use: clinic, devices: {FGT: {config: "..."}}, add_devices: [...], add_segments: [...], layout: {...}}
  (optional) topology.traffic: {rate: 1, hosts: {RECEPCION: [web, dns, mail, smb], PHONE-1: [voice]}}: office traffic generators per device; without it a profile is derived from the devices
Single-part labs may put tasks/checks/hints/solution at the top level; they become parts[0].
Usage: python3 tools/build_labs.py [--check]
"""
import re
import json, sys, glob, os, copy
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACKS = {"routing", "identity", "fortiswitch", "fortigate", "fortimanager", "fortianalyzer", "fortiswitch", "fortisiem", "fortiedr", "secops", "integration", "sdwan", "vpn", "ha"}
KINDS = {"project", "ticket", "drill", "capstone", "investigation"}
CHECK_TYPES = {"probe", "config", "dhcp", "route", "ran", "backup", "answer", "all", "state", "soc", "tunnel", "ha", "client", "sdwan", "web", "faz", "fmg", "login", "authserver", "fsso", "ospf", "bgp", "fsw", "siem", "edr", "fazinc", "attack"}


def merge_topology(t, templates, lab_id):
    t = copy.deepcopy(t or {})
    base = {}
    if t.get("use"):
        if t["use"] not in templates:
            raise SystemExit(f"{lab_id}: unknown topology template {t['use']}")
        base = copy.deepcopy(templates[t["use"]])
    if not t.get("use") and isinstance(t.get("devices"), list):
        base = {k: v for k, v in t.items() if k not in ("devices", "segments", "layout")}
        base["devices"], base["segments"], base["layout"] = t["devices"], t.get("segments", []), t.get("layout", {})
        t = {k: v for k, v in t.items() if k in ("clock", "dns", "title", "traffic")}
    devs = {d["id"]: d for d in base.get("devices", [])}
    order = [d["id"] for d in base.get("devices", [])]
    for did, over in (t.get("devices") or {}).items():
        if did not in devs:
            raise SystemExit(f"{lab_id}: override for unknown device {did}")
        d = devs[did]
        for k, v in over.items():
            if k == "config":
                d["config"] = (d.get("config", "") + "\n" + v).strip()
            elif k == "replace_config":
                d["config"] = v
            else:
                d[k] = v
    for d in t.get("add_devices") or []:
        devs[d["id"]] = d
        order.append(d["id"])
    for did in t.get("remove_devices") or []:
        devs.pop(did, None)
        order.remove(did)
    segs = [s for s in base.get("segments", []) if s.get("id") not in set(t.get("remove_segments") or [])]
    segs += t.get("add_segments") or []
    for sid, extra in (t.get("segment_members") or {}).items():
        seg = next((x for x in segs if x.get("id") == sid), None)
        if not seg:
            raise SystemExit(f"{lab_id}: segment_members for unknown segment {sid}")
        seg["members"] = seg["members"] + extra
    for s in segs:
        s["members"] = [m for m in s["members"] if (m if isinstance(m, str) else m["at"]).split(":")[0] in devs]
    layout = dict(base.get("layout", {}))
    layout.update(t.get("layout") or {})
    out = {k: v for k, v in base.items() if k not in ("devices", "segments", "layout")}
    for k in ("clock", "dns", "title", "story", "traffic"):
        if k in t:
            out[k] = t[k]
    out["devices"] = [devs[i] for i in order]
    out["segments"] = segs
    out["layout"] = layout
    return out


def normalise(lab):
    if "parts" not in lab:
        part = {"id": "a", "title": lab.get("title")}
        for k in ("brief_part", "tasks", "checks", "hints", "solution", "explain", "expect_fail", "allow_pre_pass", "events"):
            if k in lab:
                part[k.replace("brief_part", "brief")] = lab.pop(k)
        lab["parts"] = [part]
    for i, p in enumerate(lab["parts"]):
        p.setdefault("id", "abcdefghij"[i])
        for j, c in enumerate(p.get("checks", [])):
            c.setdefault("id", f"{lab['id']}.{p['id']}.{j + 1}")
    return lab


def lint(labs):
    errs, ids = [], set()
    for lab in labs:
        lid = lab.get("id", "?")
        for k in ("id", "title", "track", "modules", "tier", "order", "kind", "brief", "topology", "parts"):
            if k not in lab:
                errs.append(f"{lid}: missing {k}")
        if lid in ids:
            errs.append(f"duplicate lab id {lid}")
        ids.add(lid)
        if lab.get("track") not in TRACKS:
            errs.append(f"{lid}: unknown track {lab.get('track')}")
        for m in lab.get("modules") or []:
            if not re.fullmatch(r"M\d+\.\d\d", str(m)):
                errs.append(f"{lid}: module id {m} should look like M4.09")
        if lab.get("kind") not in KINDS:
            errs.append(f"{lid}: unknown kind {lab.get('kind')}")
        devs = {d["id"] for d in lab["topology"].get("devices", [])}
        for d in lab["topology"].get("devices", []):
            if d["id"] not in lab["topology"].get("layout", {}):
                errs.append(f"{lid}: device {d['id']} has no layout position")
        for p in lab.get("parts", []):
            if not p.get("checks"):
                errs.append(f"{lid}/{p['id']}: no checks")
            if not p.get("tasks"):
                errs.append(f"{lid}/{p['id']}: no tasks")
            if len(p.get("hints", [])) < 2:
                errs.append(f"{lid}/{p['id']}: needs at least 2 hints")
            if not p.get("solution"):
                errs.append(f"{lid}/{p['id']}: no solution")
            if not p.get("explain"):
                errs.append(f"{lid}/{p['id']}: no explanation")
            for dev in (p.get("solution") or {}):
                if dev not in devs and dev not in ("@edrtest", "@attack"):
                    errs.append(f"{lid}/{p['id']}: solution for unknown device {dev}")
            for c in p.get("checks", []):
                t = [k for k in c if k in CHECK_TYPES]
                if len(t) != 1:
                    errs.append(f"{c.get('id')}: needs exactly one check type, has {t}")
                if not c.get("text"):
                    errs.append(f"{c.get('id')}: missing text")
    return errs


def main():
    tpl_path = os.path.join(ROOT, "content", "labs", "_templates.yaml")
    raw = yaml.safe_load(open(tpl_path, encoding="utf-8")) if os.path.exists(tpl_path) else {}
    templates = {}

    def resolve(name):
        if name in templates:
            return templates[name]
        t = dict(raw[name])
        if t.get("extends"):
            resolve(t["extends"])
            t["use"] = t.pop("extends")
            templates[name] = merge_topology(t, templates, "template " + name)
        else:
            templates[name] = merge_topology(t, {}, "template " + name)
        return templates[name]

    for name in raw:
        resolve(name)
    labs = []
    for f in sorted(glob.glob(os.path.join(ROOT, "content", "labs", "*.yaml"))):
        if os.path.basename(f).startswith("_"):
            continue
        lab = yaml.safe_load(open(f, encoding="utf-8"))
        lab["topology"] = merge_topology(lab.get("topology"), templates, lab.get("id"))
        labs.append(normalise(lab))
    labs.sort(key=lambda l: (l.get("tier", 9), l.get("order", 0)))
    errs = lint(labs)
    if errs:
        print("\n".join(errs))
        raise SystemExit(f"{len(errs)} lab lint errors")
    parts = sum(len(l["parts"]) for l in labs)
    checks = sum(len(p["checks"]) for l in labs for p in l["parts"])
    out = {"labs": labs, "count": len(labs), "parts": parts, "checks": checks}
    if "--check" not in sys.argv:
        path = os.path.join(ROOT, "web", "content", "labs.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"labs: {len(labs)} labs, {parts} parts, {checks} checks")


if __name__ == "__main__":
    main()
