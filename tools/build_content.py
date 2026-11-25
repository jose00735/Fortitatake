#!/usr/bin/env python3
"""Build web/content/bundle.json from content/*.yaml and lint it (ft lint, MVP).

Usage: python3 tools/build_content.py [--check]
"""
import json, sys, glob, os, re, datetime
import yaml
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quiz_lint import lint_module

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQ = {
    "cards": ["id", "front", "back"],
    "quiz": ["id", "type", "stem"],
    "labs": ["id", "title", "goal"],
    "scenarios": ["id", "title", "situation", "ask", "right_thinking"],
    "interview": ["id", "stage", "question", "model_answer"],
    "units": ["id", "title", "body"],
}

def lint(mods):
    errs, ids = [], set()
    for m in mods:
        mid = m.get("id", "?")
        for k in ("id", "title", "order", "stage"):
            if k not in m:
                errs.append(f"{mid}: missing {k}")
        for kind, fields in REQ.items():
            for it in m.get(kind, []) or []:
                for f in fields:
                    if not it.get(f):
                        errs.append(f"{mid}: {kind} item {it.get('id')} missing {f}")
                iid = it.get("id")
                if iid in ids:
                    errs.append(f"duplicate id {iid}")
                ids.add(iid)
        units = {u["id"] for u in m.get("units", [])}
        for c in m.get("cards", []):
            if c.get("unit") and c["unit"] not in units:
                errs.append(f"{c['id']}: unknown unit {c['unit']}")
        for q in m.get("quiz", []):
            t = q.get("type")
            if t in ("single", "multi", "output"):
                n = sum(1 for o in q.get("options", []) if o.get("correct"))
                if n == 0 or (t != "multi" and n != 1):
                    errs.append(f"{q['id']}: {t} needs {'≥1' if t == 'multi' else 'exactly 1'} correct option (has {n})")
                for o in q.get("options", []):
                    if not o.get("correct") and not o.get("why_wrong"):
                        errs.append(f"{q['id']}: option {o.get('id')} has no why_wrong")
            elif t == "order":
                if len(q.get("items", [])) < 3:
                    errs.append(f"{q['id']}: order needs ≥3 items")
            elif t == "numeric":
                if not isinstance(q.get("answer"), (int, float)):
                    errs.append(f"{q['id']}: numeric needs a number answer")
            elif t == "text":
                if not q.get("accept"):
                    errs.append(f"{q['id']}: text needs accept list")
            else:
                errs.append(f"{q['id']}: unknown type {t}")
            if not q.get("explanation"):
                errs.append(f"{q['id']}: missing explanation")
        for l in m.get("labs", []):
            if l.get("faded") and "{{" not in l["faded"].get("template", ""):
                errs.append(f"{l['id']}: faded template has no blanks")
            if l.get("solo") and not l["solo"].get("required"):
                errs.append(f"{l['id']}: solo needs required lines")
        # question quality (v0.10.0 rules): enforced on modules marked quality: 2
        if (m.get("quality") or 1) >= 2:
            errs += [f"{i}: [{r}] {msg}" for i, r, msg in lint_module(m)]
    return errs

def main():
    mods = []
    for p in sorted(glob.glob(os.path.join(ROOT, "content", "*.yaml"))):
        with open(p, encoding="utf-8") as f:
            mods.append(yaml.safe_load(f))
    errs = lint(mods)
    for m in mods:
        c = {k: len(m.get(k, []) or []) for k in ("units", "cards", "quiz", "labs", "scenarios", "interview", "field_reports")}
        words = sum(len(re.findall(r"\w+", u["body"])) for u in m.get("units", []))
        print(f"{m['id']:7} {m['title'][:46]:46} " + " ".join(f"{k[:4]}={v}" for k, v in c.items()) + f" words={words}")
    if errs:
        print("\nLINT ERRORS:")
        for e in errs:
            print("  -", e)
        sys.exit(1)
    if "--check" in sys.argv:
        return
    out = {"version": datetime.datetime.now().strftime("%Y-%m-%d.%H%M"), "modules": mods}
    os.makedirs(os.path.join(ROOT, "web", "content"), exist_ok=True)
    with open(os.path.join(ROOT, "web", "content", "bundle.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    print("\nbundle written:", sum(len(m.get("cards", [])) + len(m.get("quiz", [])) for m in mods), "cards+questions")

if __name__ == "__main__":
    main()
