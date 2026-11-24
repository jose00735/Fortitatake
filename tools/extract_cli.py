#!/usr/bin/env python3
"""Turn a Fortinet CLI Reference PDF into a command schema for the FortiTatake lab CLI.

Usage:
  python3 tools/extract_cli.py <reference.pdf> <out.json> [--product fortios] [--version 8.0.2]

What goes into the schema (facts about the command tree only, no Fortinet prose):
  paths    "firewall policy" -> {t: table|object, k: edit key, a: {attr: spec}, c: {child: node}}
  spec     {y: type, o: [options], d: default, mn/mx: integer range, ml: max length, m: 1 if multi-value}
  cmds     ["diagnose debug flow trace start <xxx>", "execute ping <host>", ...]
Descriptions are deliberately left out so the generated file can live in a public repo.
"""
import json, re, subprocess, sys, os, argparse

FOOTER = re.compile(r"^\s*(FortiOS|FortiManager|FortiAnalyzer) [\d.]+ CLI Reference\s+\d+\s*$|^\s*Fortinet Inc\.\s*$")
TOP = re.compile(r"^config ([a-z0-9][a-z0-9-]*(?: [a-z0-9][a-z0-9-]*)*)\s*$")
CMD = re.compile(r"^(diagnose|execute|get|show) [a-z0-9]")


def text_of(pdf):
    out = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if not FOOTER.match(l)]


def node():
    return {"t": "object", "a": {}, "c": {}}


def spec_from_syntax(rest):
    rest = rest.strip()
    s = {}
    if rest.startswith("["):
        opts = [o for o in rest.strip("[]").split("|") if o and o != "..."]
        s["y"] = "option"
        s["o"] = opts
        if "..." in rest:
            s["partial"] = 1
    elif rest.startswith("{option1}"):
        s["y"] = "option"
        s["m"] = 1
        s["o"] = []
        s["partial"] = 1
    elif rest.startswith("<") and "," in rest:
        s["y"] = "string"
        s["m"] = 1
    elif rest.startswith("{"):
        s["y"] = rest.strip("{}").split("}")[0]
    else:
        s["y"] = "string"
    return s


def parse_syntax(lines, i, root_path):
    """Parse the code block that starts at lines[i] ('config <path>'). Returns (tree, next index)."""
    stack = []
    tree = None
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.strip()
        i += 1
        if not line or line.startswith("Description:"):
            continue
        if line.startswith("config "):
            nd = node()
            name = line[7:].strip()
            if stack:
                stack[-1]["c"][name] = nd
            else:
                tree = nd
            stack.append(nd)
            continue
        if line.startswith("edit "):
            if stack:
                stack[-1]["t"] = "table"
                stack[-1]["k"] = line[5:].strip().strip("<>")
            continue
        if line == "next":
            continue
        if line == "end":
            stack.pop()
            if not stack:
                return tree, i
            continue
        if line.startswith("set ") and stack:
            parts = line[4:].split(None, 1)
            stack[-1]["a"][parts[0]] = spec_from_syntax(parts[1] if len(parts) > 1 else "")
            continue
        if line.startswith("unset ") or line.startswith("append ") or line.startswith("select "):
            continue
        # anything else ends a broken block
        if stack and raw and not raw.startswith(" "):
            return tree, i - 1
    return tree, i


def iter_nodes(nd, name=""):
    yield name, nd
    for k, c in nd["c"].items():
        yield from iter_nodes(c, k)


INT_TYPES = {"integer"}


def parse_tables(lines, i, tree, stop):
    """Read the parameter tables after a syntax block and merge types, options, defaults, ranges."""
    order = list(iter_nodes(tree))
    cur = tree
    pos = 0
    cols = None
    param = None
    size_buf = []
    mode = None  # None | "options"
    optcol = None

    def flush():
        nonlocal param, size_buf
        if param is not None:
            sp = cur["a"].setdefault(param["name"], {"y": param.get("type") or "string"})
            if param.get("type"):
                sp["y"] = param["type"]
            if param.get("default") not in (None, "", "-"):
                sp["d"] = param["default"]
            if param.get("opts"):
                if sp.get("partial") or not sp.get("o"):
                    sp["o"] = param["opts"]
                    sp.pop("partial", None)
            st = " ".join(size_buf)
            m = re.search(r"Minimum\s+value:\s*(-?\d+)\s+Maximum\s+value:\s*(-?\d+)", st)
            if m:
                sp["mn"], sp["mx"] = int(m.group(1)), int(m.group(2))
            m = re.search(r"Maximum\s+length:\s*(\d+)", st)
            if m:
                sp["ml"] = int(m.group(1))
        param = None
        size_buf = []

    while i < stop:
        raw = lines[i]
        i += 1
        if not raw.strip():
            continue
        m = re.match(r"^   config ([a-z0-9][a-z0-9-]*(?: [a-z0-9-]+)*)\s*$", raw)
        if m:
            flush()
            name = m.group(1)
            mode = None
            if name == next(iter([n for n, _ in order[:1]]), None) or pos == 0 and " " in name:
                cur = tree
                continue
            for j in range(pos, len(order)):
                if order[j][0] == name:
                    cur = order[j][1]
                    pos = j + 1
                    break
            continue
        if re.match(r"^\s+Parameter\s+Description\s+Type", raw):
            # a page break repeats the header; the current parameter may continue below it
            off = (optcol - cols["Parameter"]) if (cols and optcol is not None) else None
            cols = {k: raw.index(k) for k in ("Parameter", "Description", "Type")}
            cols["Size"] = raw.index("Size") if "Size" in raw else len(raw) + 10
            cols["Default"] = raw.index("Default") if "Default" in raw else len(raw) + 40
            if off is not None:
                optcol = cols["Parameter"] + off
            continue
        if cols is None:
            continue
        m = re.match(r"^(\s+)Option\s+Description\s*$", raw)
        if m:
            mode = "options"
            optcol = len(m.group(1))
            continue
        ind = len(raw) - len(raw.lstrip())
        if abs(ind - cols["Parameter"]) <= 1:
            mode = None
            name = raw[ind:].split("  ")[0].strip().rstrip("*").strip()
            ttxt = raw[cols["Type"] - 1:cols["Size"] - 1].strip().split(" ")[0] if len(raw) > cols["Type"] else ""
            if not ttxt and param is not None and param["name"].endswith("-"):
                param["name"] += name  # wrapped parameter name
                continue
            if not re.match(r"^[a-z0-9][a-z0-9_.-]*$", name) or re.match(r"^\d+\.\d", name):
                continue
            flush()
            param = {"name": name, "type": ttxt, "opts": []}
            if len(raw) > cols["Size"]:
                size_buf.append(raw[cols["Size"] - 1:cols["Default"] - 1].strip())
            if len(raw) > cols["Default"]:
                param["default"] = raw[cols["Default"] - 2:].strip()
            continue
        if param is None:
            continue
        if mode == "options" and optcol is not None and abs(ind - optcol) <= 3:
            tok = raw[ind:].split("  ")[0].strip()
            if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.:/+-]*$", tok):
                if param["opts"] and param["opts"][-1].endswith("-"):
                    param["opts"][-1] += tok
                else:
                    param["opts"].append(tok)
            continue
        if param.get("type", "").endswith("-") and len(raw) > cols["Type"]:
            t2 = raw[cols["Type"] - 1:cols["Size"] - 1].strip().split(" ")[0]
            if t2:
                param["type"] += t2
        dflt = param.get("default") or ""
        if dflt.endswith("-") and len(raw) > cols["Default"] - 2:
            more = raw[cols["Default"] - 2:].strip()
            if more and "  " not in more:
                param["default"] = dflt + more
        if mode is None and len(raw) > cols["Size"] - 1 and ind >= cols["Description"]:
            seg = raw[cols["Size"] - 1:cols["Default"] - 1].strip()
            if seg:
                size_buf.append(seg)
            if not param.get("default") and len(raw) > cols["Default"] and ind < cols["Default"] - 2:
                pass
    flush()


def clean(nd):
    for sp in nd["a"].values():
        sp.pop("partial", None)
        if sp.get("y") == "option" and not sp.get("o"):
            sp.pop("o", None)
    for c in nd["c"].values():
        clean(c)
    if not nd["c"]:
        del nd["c"]
    if nd["t"] == "object":
        del nd["t"]
    return nd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pdf")
    ap.add_argument("out")
    ap.add_argument("--product", default="fortios")
    ap.add_argument("--version", default="8.0.2")
    a = ap.parse_args()
    lines = text_of(a.pdf)
    starts = [i for i, l in enumerate(lines) if TOP.match(l)]
    paths, cmds = {}, set()
    for idx, s in enumerate(starts):
        path = TOP.match(lines[s]).group(1)
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        # first syntax block line: an indented 'config <path>'
        j = s + 1
        while j < end and lines[j].strip() != "config " + path:
            j += 1
        if j >= end:
            continue
        tree, k = parse_syntax(lines, j, path)
        if not tree:
            continue
        parse_tables(lines, k, tree, end)
        if path in paths:
            continue
        paths[path] = clean(tree)
    for i, l in enumerate(lines):
        if CMD.match(l) and not l.startswith(" "):
            # syntax line is the next indented line starting with the same words
            name = l.strip()
            syn = name
            for j in range(i + 1, min(i + 8, len(lines))):
                t = lines[j].strip()
                if t.startswith(name):
                    syn = t
                    break
            cmds.add(syn)
    out = {"product": a.product, "version": a.version, "paths": paths, "cmds": sorted(cmds)}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(out, f, separators=(",", ":"), sort_keys=True)
    print(f"{a.product} {a.version}: {len(paths)} config paths, {len(cmds)} commands -> {a.out} ({os.path.getsize(a.out)//1024} KB)")


if __name__ == "__main__":
    main()
