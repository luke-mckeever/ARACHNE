#!/usr/bin/env python3
"""Check the interface translations in static/i18n/: every language file has the same phrases,
and each translation keeps the phrase's placeholders ({n}, {time}, ...) and inline tags (<0>..</0>).

    python tools/check_i18n.py

To add a phrase: add it to every file in static/i18n/ (English text as the key). To add a language:
copy a file, translate the values, and add the language to LANGS in static/js/i18n.js."""
import json
import os
import re
import sys

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static", "i18n")
TOKENS = re.compile(r"\{\w+\}|</?\d+/?>")


def main():
    files = sorted(f for f in os.listdir(DIR) if f.endswith(".json"))
    data = {}
    for f in files:
        with open(os.path.join(DIR, f), encoding="utf-8") as fh:
            data[f] = {k: v for k, v in json.load(fh).items() if not k.startswith("_")}
    keys = set().union(*(d.keys() for d in data.values()))
    problems = []
    for f, d in data.items():
        for k in sorted(keys - d.keys()):
            problems.append(f"{f}: missing {k!r}")
        for k, v in d.items():
            if not isinstance(v, str) or not v.strip():
                problems.append(f"{f}: empty translation for {k!r}")
            elif sorted(TOKENS.findall(k)) != sorted(TOKENS.findall(v)):
                problems.append(f"{f}: placeholders differ in {k!r} -> {v!r}")
    for p in problems:
        print(p)
    print(f"{len(files)} languages, {len(keys)} phrases, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
