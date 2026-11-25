#!/usr/bin/env python3
"""Rewrite quiz items in place without reformatting the rest of a module file.

  python3 tools/quiz_patch.py --dump M4.12        # compact view of a module's quiz
  python3 tools/quiz_patch.py patch.yaml [...]    # apply patches

Patch file:
  module: M4.12
  quality: 2                 # optional: add/replace `quality:` after `order:`
  items:
    M4.12.q01:
      stem: "..."            # optional
      tier: 3                # optional
      format: first-step     # optional (first-step | answer-reason | not-work)
      output: |              # optional, for type output
        ...
      type: output           # optional
      options:
        - {id: a, text: "...", correct: true}
        - {id: b, text: "...", trap: near-miss, why_wrong: "..."}
      accept: ["..."]        # optional, for text items
  add: |                     # optional: raw YAML items appended to the quiz list
    - id: M4.12.q20
      ...
"""
import glob, json, os, re, sys
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def q(s):
    return json.dumps(str(s), ensure_ascii=False)


def opt_line(o):
    parts = [f"id: {o['id']}", f"text: {q(o['text'])}"]
    if o.get("correct"):
        parts.append("correct: true")
    if o.get("trap"):
        parts.append(f"trap: {o['trap']}")
    if o.get("why_wrong"):
        parts.append(f"why_wrong: {q(o['why_wrong'])}")
    return "      - {" + ", ".join(parts) + "}\n"


def find_file(mid):
    for p in glob.glob(os.path.join(ROOT, "content", "*.yaml")):
        with open(p, encoding="utf-8") as f:
            if re.search(rf"^id: {re.escape(mid)}\s*$", f.read(), re.M):
                return p
    raise SystemExit(f"module {mid} not found")


def block_end(lines, i, indent):
    """First line after i whose indentation is <= indent (ignoring blanks)."""
    j = i + 1
    while j < len(lines):
        ln = lines[j]
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
            return j
        j += 1
    return j


def set_field(lines, start, end, key, value_lines):
    """Replace (or insert after tier/type) `    key:` inside item lines[start:end]."""
    for i in range(start, end):
        if re.match(rf"^    {key}:", lines[i]):
            e = block_end(lines, i, 4)
            lines[i:e] = value_lines
            return
    # insert after tier (or type)
    for anchor in ("tier", "type"):
        for i in range(start, end):
            if re.match(rf"^    {anchor}:", lines[i]):
                lines[i + 1:i + 1] = value_lines
                return
    lines[start + 1:start + 1] = value_lines


def item_range(lines, qid):
    for i, ln in enumerate(lines):
        if re.match(rf"^  - id: {re.escape(qid)}\s*$", ln):
            j = i + 1
            while j < len(lines) and not re.match(r"^  - id: |^\S", lines[j]):
                j += 1
            return i, j
    raise SystemExit(f"item {qid} not found")


def scalar(key, v):
    if isinstance(v, str) and "\n" in v:
        body = "".join("      " + l + "\n" if l else "\n" for l in v.rstrip("\n").split("\n"))
        return [f"    {key}: |\n", *body.splitlines(True)]
    if isinstance(v, (list, dict)):
        return [f"    {key}: {json.dumps(v, ensure_ascii=False)}\n"]
    if isinstance(v, str):
        return [f"    {key}: {q(v)}\n"]
    return [f"    {key}: {json.dumps(v)}\n"]


def apply(path):
    with open(path, encoding="utf-8") as f:
        p = yaml.safe_load(f)
    fn = find_file(p["module"])
    with open(fn, encoding="utf-8") as f:
        lines = f.readlines()
    if p.get("quality"):
        idx = [i for i, l in enumerate(lines) if l.startswith("quality:")]
        if idx:
            lines[idx[0]] = f"quality: {p['quality']}\n"
        else:
            o = [i for i, l in enumerate(lines) if l.startswith("order:")][0]
            lines.insert(o + 1, f"quality: {p['quality']}\n")
    for qid, ch in (p.get("items") or {}).items():
        for key in ("type", "tier", "format", "stem", "output", "answer", "accept", "explanation", "items"):
            if key in ch:
                s, e = item_range(lines, qid)
                set_field(lines, s, e, key, scalar(key, ch[key]))
        if "options" in ch:
            s, e = item_range(lines, qid)
            set_field(lines, s, e, "options", ["    options:\n"] + [opt_line(o) for o in ch["options"]])
        if ch.get("retire"):
            s, e = item_range(lines, qid)
            set_field(lines, s, e, "retired", ["    retired: true\n"])
    if p.get("add"):
        qi = [i for i, l in enumerate(lines) if l.startswith("quiz:")][0]
        e = block_end(lines, qi, 0)
        while e > qi and not lines[e - 1].strip():
            e -= 1
        add = "".join("  " + l + "\n" if l.strip() else "\n" for l in p["add"].rstrip("\n").split("\n"))
        lines[e:e] = add.splitlines(True)
    text = "".join(lines)
    yaml.safe_load(text)  # must still parse
    with open(fn, "w", encoding="utf-8") as f:
        f.write(text)
    print("patched", os.path.basename(fn))


def dump(mid):
    with open(find_file(mid), encoding="utf-8") as f:
        m = yaml.safe_load(f)
    for it in m.get("quiz", []) or []:
        print(f"## {it['id']} {it.get('type')} t{it.get('tier')} {it.get('format', '')}")
        print("S:", str(it.get("stem", "")).strip())
        if it.get("output"):
            print("OUT:", str(it["output"]).strip().replace("\n", " ⏎ "))
        for o in it.get("options", []) or []:
            print(f"  {o['id']}{'*' if o.get('correct') else ' '} {o['text']}  || {o.get('why_wrong', '')}")
        if it.get("items"):
            print("  items:", it["items"])
        if it.get("accept"):
            print("  accept:", it["accept"], "answer:", it.get("answer"))
        if it.get("answer") is not None and not it.get("accept"):
            print("  answer:", it.get("answer"))
        print("E:", str(it.get("explanation", "")).strip())


if __name__ == "__main__":
    if sys.argv[1] == "--dump":
        dump(sys.argv[2])
    else:
        for a in sys.argv[1:]:
            apply(a)
