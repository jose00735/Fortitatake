#!/usr/bin/env python3
"""Question-quality lint and cue-bot blind-guess test (the v0.10.0 rules).

A question must not be answerable from test-taking cues. The lint looks at the shape of each item;
the cue bot actually tries to answer every item from cues alone (length, hedges, stem overlap,
absolute words, specificity) without knowing anything, and reports how often it wins.

Usage:
  python3 tools/quiz_lint.py              # lint report + cue-bot scores per stage
  python3 tools/quiz_lint.py --strict     # exit 1 if any module fails the lint
  python3 tools/quiz_lint.py --list M9.03 # print each finding for one module
Used by build_content.py: modules with `quality: 2` must pass; from v0.10.0 every module has it.
"""
import glob, os, re, sys, statistics
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HEDGES = re.compile(r"\b(usually|typically|generally|often|may|might|can|could|depends|unless|only if|in most|tends? to|likely|where possible|if needed|by default)\b", re.I)
ABSOLUTE = re.compile(r"\b(always|never|only|every|none|completely|entirely|guarantee[sd]?|impossible|must)\b", re.I)
STOP = set("""the and for that with this from what which when where your into than then them they their there does have
has had will would should could about after before more most each such only also just very over under while being been
were what's it's isn't don't can't won't you are was its not but our out who how why use used using via per one two""".split())
GENERIC_WHY = re.compile(r"^(no|wrong|incorrect|unrelated|not relevant|irrelevant|too broad|too narrow|nope|false)\.?$", re.I)
TRAPS = {"misconception", "irrelevant", "near-miss"}


def words(s):
    return [w for w in re.findall(r"[a-z0-9][a-z0-9\-\.]{3,}", str(s).lower()) if w not in STOP]


def choice_items(m):
    for q in m.get("quiz", []) or []:
        if q.get("retired"):
            continue
        if q.get("type") in ("single", "multi", "output") and q.get("options"):
            yield q


def lint_item(q):
    """Return a list of (rule, message) findings for one choice item."""
    out = []
    opts = q["options"]
    right = [o for o in opts if o.get("correct")]
    wrong = [o for o in opts if not o.get("correct")]
    tier = int(q.get("tier", 1) or 1)
    if len(opts) < 4:
        out.append(("options", f"{len(opts)} options; use at least 4"))
    if not right or not wrong:
        return out
    L = [len(str(o["text"])) for o in opts]
    mean = statistics.mean(L)
    if mean >= 14:
        for o in right:
            d = (len(str(o["text"])) - mean) / mean
            if abs(d) > 0.25:
                out.append(("length", f"right option is {'+' if d > 0 else ''}{round(d * 100)}% vs the average length"))
        # the right answer is the single longest by a clear margin
        if len(right) == 1:
            longest = max(L)
            if len(str(right[0]["text"])) == longest and sorted(L)[-2] < 0.85 * longest:
                out.append(("length", "right option is clearly the longest"))
    for name, rx in (("hedge", HEDGES), ("paren", re.compile(r"[()]"))):
        r_has = any(rx.search(str(o["text"])) for o in right)
        w_has = any(rx.search(str(o["text"])) for o in wrong)
        if r_has and not w_has:
            out.append((name, f"{'qualifier' if name == 'hedge' else 'parentheses'} only in the right option"))
    a_r = any(ABSOLUTE.search(str(o["text"])) for o in right)
    a_w = sum(1 for o in wrong if ABSOLUTE.search(str(o["text"])))
    if a_w and not a_r:
        out.append(("absolute", "absolute words (always/never/only…) only in wrong options"))
    stem = set(words(q.get("stem", "")))
    ov = lambda o: len(stem & set(words(o["text"])))
    if len(right) == 1 and ov(right[0]) >= 2 and ov(right[0]) > max(ov(o) for o in wrong):
        out.append(("stem", "right option repeats the stem's words more than any distractor"))
    for o in wrong:
        why = str(o.get("why_wrong", "")).strip()
        if not why or GENERIC_WHY.match(why) or len(why.split()) < 5:
            out.append(("why", f"option {o.get('id')}: why_wrong missing or too generic"))
        if o.get("trap") not in TRAPS:
            out.append(("trap", f"option {o.get('id')}: trap must be one of {sorted(TRAPS)}"))
    near = sum(1 for o in wrong if o.get("trap") == "near-miss")
    need = 2 if tier >= 3 else 1 if tier >= 2 else 0
    if q.get("type") == "multi":  # several right answers: one near-miss among the wrong ones is enough
        need = min(need, 1)
    if near < need:
        out.append(("near", f"tier {tier} needs {need} near-miss distractor(s), has {near}"))
    return out


def lint_text(q):
    out = []
    acc = [str(a) for a in q.get("accept", []) or []]
    if any(len(a.strip("~")) < 3 for a in acc):
        out.append(("loose", "accepted answer shorter than 3 characters"))
    return out


def lint_module(m):
    """Findings for a module: list of (item id, rule, message)."""
    f = []
    for q in m.get("quiz", []) or []:
        if q.get("retired"):
            continue
        t = q.get("type")
        if t in ("single", "multi", "output") and q.get("options"):
            f += [(q["id"], r, msg) for r, msg in lint_item(q)]
        elif t == "text":
            f += [(q["id"], r, msg) for r, msg in lint_text(q)]
    # across a module the right answer must not usually be the longest option
    single = [q for q in choice_items(m) if q.get("type") != "multi"]
    if len(single) >= 4:
        longest = sum(1 for q in single if max(q["options"], key=lambda o: len(str(o["text"]))).get("correct"))
        if longest / len(single) > 0.35:
            f.append((m["id"], "longest", f"right option is the longest in {longest} of {len(single)} items (max 35%)"))
    hard = [q for q in m.get("quiz", []) or [] if int(q.get("tier", 1) or 1) >= 3 and not q.get("retired")]
    if hard and not any(q.get("type") == "output" or q.get("format") in ("first-step", "answer-reason", "not-work") for q in hard):
        f.append((m["id"], "formats", "no output-based or best-first-step question at tier 3+"))
    return f


# ---------------- cue bot ----------------
def cue_score(q, o, opts):
    """How attractive an option looks to someone who knows nothing about the subject."""
    t = str(o["text"])
    L = [len(str(x["text"])) for x in opts]
    s = 0.0
    s += 2.0 * (len(t) - statistics.mean(L)) / (statistics.pstdev(L) or 1)  # longest wins
    s += 1.0 if HEDGES.search(t) else 0
    s += 0.7 if "(" in t else 0
    s -= 1.2 if ABSOLUTE.search(t) else 0
    s += 0.6 * len(set(words(q.get("stem", ""))) & set(words(t)))
    s += 0.3 * len(re.findall(r"[,;]| and ", t))  # more specific-sounding
    s -= 1.5 if re.search(r"\b(delete|disable|reboot|ignore|nothing|wait)\b", t, re.I) else 0  # "obviously wrong" verbs
    return s


def cue_guess(q):
    opts = q["options"]
    sc = [(cue_score(q, o, opts), o["id"]) for o in opts]
    sc.sort(reverse=True)
    if q.get("type") == "multi":
        med = statistics.median(s for s, _ in sc)
        return sorted(i for s, i in sc if s > med) or [sc[0][1]]
    return [sc[0][1]]


def cue_test(mods):
    """Per stage: (right, total, chance) for the cue bot."""
    res = {}
    for m in mods:
        st = str(m.get("stage", "?"))
        for q in choice_items(m):
            right = sorted(o["id"] for o in q["options"] if o.get("correct"))
            g = cue_guess(q)
            r = res.setdefault(st, [0, 0, 0.0])
            r[0] += int(g == right)
            r[1] += 1
            r[2] += 1 / len(q["options"]) if q.get("type") != "multi" else 1 / (2 ** len(q["options"]) - 1)
    return res


def load():
    mods = []
    for p in sorted(glob.glob(os.path.join(ROOT, "content", "*.yaml"))):
        with open(p, encoding="utf-8") as f:
            mods.append(yaml.safe_load(f))
    return mods


def main():
    mods = load()
    if "--lens" in sys.argv:  # option lengths and the cue bot's pick, per item
        mid = sys.argv[sys.argv.index("--lens") + 1]
        for m in mods:
            if m["id"] == mid:
                for q in choice_items(m):
                    print(q["id"], " ".join(f"{o['id']}{'*' if o.get('correct') else ''}={len(str(o['text']))}" for o in q["options"]), "bot:", cue_guess(q))
        return
    strict = "--strict" in sys.argv
    only = sys.argv[sys.argv.index("--list") + 1] if "--list" in sys.argv else None
    bad = 0
    print(f"{'module':8} {'items':>5} {'flagged':>7}  rules")
    for m in mods:
        f = lint_module(m)
        n = sum(1 for _ in choice_items(m))
        items = {i for i, _, _ in f}
        rules = {}
        for _, r, _ in f:
            rules[r] = rules.get(r, 0) + 1
        need = strict or m.get("quality", 1) >= 2
        mark = "✗" if f and need else " "
        bad += bool(f and need)
        print(f"{mark}{m['id']:7} {n:5} {len(items):7}  " + " ".join(f"{k}={v}" for k, v in sorted(rules.items())))
        if only == m["id"]:
            for i, r, msg in f:
                print(f"    {i}: [{r}] {msg}")
    print("\ncue bot (answers from test-taking cues only):")
    tot = [0, 0, 0.0]
    for st, (r, n, ch) in sorted(cue_test(mods).items()):
        tot = [tot[0] + r, tot[1] + n, tot[2] + ch]
        print(f"  {st:5} {r:4}/{n:<4} = {100 * r / n:5.1f}%   chance {100 * ch / n:4.1f}%")
    if tot[1]:
        print(f"  all   {tot[0]:4}/{tot[1]:<4} = {100 * tot[0] / tot[1]:5.1f}%   chance {100 * tot[2] / tot[1]:4.1f}%")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
