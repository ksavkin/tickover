#!/usr/bin/env python3
"""Regenerate assets/prices.json — the price snapshot the binary embeds.

    python3 -I tools/update-prices.py LITELLM_SHA MODELS_DEV_SHA

Both sources are read at the commit given, never at a branch head, and the
snapshot's date is the newer of the two commits' dates, not the day the
script ran: the same two shas always produce the same file, and a price
change shows up as a diff someone reviews. Nothing here runs at build time
or at run time: the app never touches the network for prices.

Sources, in fixed precedence:

1. LiteLLM's model_prices_and_context_window.json (MIT). Only the
   first-party list price is taken: bare keys whose provider is
   `anthropic` or `openai`, `gemini/*` (Google AI
   Studio) and `xai/*`. Resellers, clouds and routers (azure, bedrock,
   vertex, perplexity, …) are skipped even when they carry the same id —
   their rates differ from the list price, and which one a bare id meant is
   exactly the guess this file exists to avoid.
2. models.dev's providers/<p>/models/*.toml (MIT), only for ids LiteLLM
   has no first-party price for; where two of its providers carry the same
   id, the one earlier in MODELS_DEV_PROVIDERS wins.

Base-tier rates only. A history row is an hourly aggregate, so a
per-request tier (LiteLLM's `*_above_200k_tokens` and
`cache_creation_input_token_cost_above_1hr`) cannot be applied to it after
the fact; the snapshot does not pretend to. LiteLLM's plain
`cache_creation_input_token_cost` is the 5-minute write rate.

A model needs a non-zero input and output rate to be listed: the zeros
LiteLLM carries are on free or experimental endpoints, which have no list
price to be equivalent to. A cache class the source leaves out prices at
the input rate — OpenAI and Gemini bill a cache *write* as plain input, and
an uncached rate is the honest ceiling for a cache read nobody published a
discount for — while a cache rate stated as 0 stays 0.
"""

import io
import json
import math
import os
import re
import subprocess
import sys
import tarfile
import tomllib

LITELLM_REPO = "BerriAI/litellm"
LITELLM_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/{sha}/"
    "model_prices_and_context_window.json"
)
MODELS_DEV_REPO = "sst/models.dev"
MODELS_DEV_URL = "https://codeload.github.com/sst/models.dev/tar.gz/{sha}"
COMMIT_URL = "https://api.github.com/repos/{repo}/commits/{sha}"

# (key prefix, litellm_provider) pairs that carry a first-party list price.
LITELLM_FIRST_PARTY = [
    ("", "anthropic"),
    ("", "openai"),
    ("gemini/", "gemini"),
    ("xai/", "xai"),
]
MODELS_DEV_PROVIDERS = ["anthropic", "openai", "google", "xai"]
MODES = {"chat", "responses", "completion"}


def fetch(url):
    # curl, not urllib: a python.org build on macOS ships without a CA
    # bundle until someone runs its "Install Certificates" step.
    return subprocess.run(
        ["curl", "-sSfL", "--max-time", "120", url], check=True, capture_output=True
    ).stdout


def commit_date(repo, sha):
    """The commit's own date, YYYY-MM-DD — what "prices as of" means."""
    doc = json.loads(fetch(COMMIT_URL.format(repo=repo, sha=sha)))
    return doc["commit"]["committer"]["date"][:10]


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def per_m(v):
    """USD per token → USD per 1M tokens, rounded off float noise.
    `None` only when the field is absent; a stated 0 stays 0; a value that
    is not a number passes through untouched for valid() to refuse."""
    if v is None or not is_num(v):
        return v
    return float(round(v * 1_000_000, 6))


def is_free(e):
    """Zero input and output: a free or experimental endpoint, which has no
    list price to be equivalent to. Counted, not listed one by one."""
    return e["in"] == 0 and e["out"] == 0


def valid(e):
    """A row a price can be read from: every rate a finite number, input
    and output above zero, cache rates not below it. Anything else is a data
    error upstream, reported and left out rather than written into the
    snapshot for the app to multiply by."""
    rates = [e["in"], e["out"], e["cr"], e["cw"]]
    ok = all(is_num(r) and math.isfinite(r) and r >= 0 for r in rates)
    return ok and e["in"] > 0 and e["out"] > 0


def entry(inp, out, cr, cw, src):
    return {
        "in": inp,
        "out": out,
        "cr": inp if cr is None else cr,
        "cw": inp if cw is None else cw,
        "src": src,
    }


def from_litellm(raw):
    data = json.loads(raw)
    models = {}
    free = []
    per_item = []
    for prefix, provider in LITELLM_FIRST_PARTY:
        for key, v in data.items():
            if not isinstance(v, dict) or v.get("litellm_provider") != provider:
                continue
            if not key.startswith(prefix) or "/" in key[len(prefix):]:
                continue
            if v.get("mode") not in MODES:
                continue
            inp = per_m(v.get("input_cost_per_token"))
            out = per_m(v.get("output_cost_per_token"))
            if inp is None or out is None:
                # Image, audio and embedding rows bill per item, not per
                # token; counted, not listed one by one.
                per_item.append(key)
                continue
            mid = key[len(prefix):].lower()
            e = entry(
                inp,
                out,
                per_m(v.get("cache_read_input_token_cost")),
                per_m(v.get("cache_creation_input_token_cost")),
                "litellm",
            )
            if not valid(e):
                if is_free(e):
                    free.append(key)
                else:
                    print(f"skipped {key}: rates {e}", file=sys.stderr)
                continue
            models.setdefault(mid, e)
    if free:
        print(f"skipped {len(free)} LiteLLM rows priced at zero (free tiers)", file=sys.stderr)
    if per_item:
        print(f"skipped {len(per_item)} LiteLLM rows without a per-token price", file=sys.stderr)
    return models


def from_models_dev(raw):
    found = []
    unpriced = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for m in tar.getmembers():
            parts = m.name.split("/")
            # <repo>-<sha>/providers/<provider>/models/<id>.toml
            if (
                len(parts) != 5
                or parts[1] != "providers"
                or parts[2] not in MODELS_DEV_PROVIDERS
                or parts[3] != "models"
                or not parts[4].endswith(".toml")
                or not m.isfile()
            ):
                continue
            doc = tomllib.load(tar.extractfile(m))
            # Schema 2: USD per 1M tokens under cost.text.{input,output}. A
            # new schema stops the run rather than silently dropping the
            # whole models.dev half.
            if doc.get("schema") != 2:
                sys.exit(f"{m.name}: models.dev schema {doc.get('schema')!r}, expected 2")
            cost = doc.get("cost", {})
            text = cost.get("text", {}) if isinstance(cost, dict) else None
            i = text.get("input", {}) if isinstance(text, dict) else None
            o = text.get("output", {}) if isinstance(text, dict) else None
            cache = i.get("cache", {}) if isinstance(i, dict) else None
            if not all(isinstance(t, dict) for t in (cost, text, i, o, cache)):
                print(f"skipped {m.name}: cost is not laid out as tables", file=sys.stderr)
                continue
            if "price" not in i or "price" not in o:
                # Audio, image and retired models publish no per-token
                # text price; counted, not listed one by one.
                unpriced.append(m.name)
                continue
            write = cache.get("write")
            # Anthropic rows split the write by cache lifetime; the 5-minute
            # rate is the base one, the same choice made for LiteLLM above.
            if isinstance(write, dict):
                write = write.get("5m")
            # Numbers as floats, so 30 and 30.0 are one diff; anything else
            # stays as it is for valid() to refuse.
            num = lambda v: float(v) if is_num(v) else v
            e = entry(num(i["price"]), num(o["price"]), num(cache.get("read")), num(write), "models.dev")
            if not valid(e):
                print(f"skipped {m.name}: rates {e}", file=sys.stderr)
                continue
            found.append((MODELS_DEV_PROVIDERS.index(parts[2]), parts[4][: -len(".toml")].lower(), e))
    if unpriced:
        print(f"skipped {len(unpriced)} models.dev files without a text price", file=sys.stderr)
    models = {}
    # Archive order is not a policy: sort by provider precedence, then id.
    for _, mid, e in sorted(found, key=lambda f: (f[0], f[1])):
        models.setdefault(mid, e)
    return models


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: python3 -I tools/update-prices.py LITELLM_SHA MODELS_DEV_SHA")
    litellm_sha, models_dev_sha = sys.argv[1], sys.argv[2]
    # A branch or tag name would fetch whatever it points at today, and the
    # same arguments would stop producing the same file.
    for sha in (litellm_sha, models_dev_sha):
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            sys.exit(f"{sha!r} is not a full 40-character commit sha")
    models = from_litellm(fetch(LITELLM_URL.format(sha=litellm_sha)))
    for mid, e in from_models_dev(fetch(MODELS_DEV_URL.format(sha=models_dev_sha))).items():
        models.setdefault(mid, e)
    head = {
        "snapshot": max(
            commit_date(LITELLM_REPO, litellm_sha),
            commit_date(MODELS_DEV_REPO, models_dev_sha),
        ),
        "litellm": litellm_sha,
        "models_dev": models_dev_sha,
    }
    # One model per line, so a price change is a one-line diff.
    lines = [
        f"{json.dumps(k)}:{json.dumps(v, separators=(',', ':'))}"
        for k, v in sorted(models.items())
    ]
    path = "assets/prices.json"
    # Written aside and renamed: an interrupted run must not leave a
    # truncated file for the next build to embed.
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        f.write(json.dumps(head, separators=(",", ":"))[:-1])
        f.write(',"models":{\n' + ",\n".join(lines) + "\n}}\n")
    os.replace(tmp, path)
    print(f"{path}: {len(models)} models", file=sys.stderr)


if __name__ == "__main__":
    main()
