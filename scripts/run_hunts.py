#!/usr/bin/env python3
"""Run every hunt's queries against Elasticsearch and record the evidence.

For each hunts/*/hunt.yml this script:
  1. executes each Lucene query exactly as written in the file,
  2. records the hit count, the matching events, and any stacking
     (count-by-field) results,
  3. checks the count against the hunt's stated expectation,
  4. writes results/<hunt-id>.json and prints a summary.

It exits non-zero if any expectation fails, so CI goes red when a query
stops finding what its write-up claims it finds.

Usage:
  python3 scripts/run_hunts.py            # all hunts
  python3 scripts/run_hunts.py H-001      # one hunt
"""

import datetime as dt
import glob
import json
import os
import socket
import subprocess
import sys

import yaml

from es import ES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_EVENTS = 50  # events stored per query in the results file


def git_sha():
    try:
        return subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return None


def stack(es, index, lucene, fields):
    """Count matching events by one or more fields (fleet stacking)."""
    if len(fields) == 1:
        agg = {"terms": {"field": fields[0], "size": 100}}
    else:
        agg = {"multi_terms": {"terms": [{"field": f} for f in fields], "size": 100}}
    body = {"size": 0, "query": {"query_string": {"query": lucene}}, "aggs": {"stack": agg}}
    resp = es.request("POST", f"/{index}/_search", body)
    return [{"key": b.get("key_as_string", b["key"]), "count": b["doc_count"]}
            for b in resp["aggregations"]["stack"]["buckets"]]


def check(expect, hits):
    if not expect:
        return True, "no expectation set"
    if "hits" in expect:
        return hits == expect["hits"], f"expected exactly {expect['hits']}"
    lo, hi = expect.get("min_hits", 0), expect.get("max_hits")
    ok = hits >= lo and (hi is None or hits <= hi)
    return ok, f"expected {lo}..{hi if hi is not None else 'any'}"


def run_hunt(es, path, meta):
    with open(path) as fh:
        hunt = yaml.safe_load(fh)
    index = hunt["index"]
    fields = hunt.get("fields", [])
    sort_field = hunt.get("sort")
    out = {"id": hunt["id"], "title": hunt["title"], "attack": hunt.get("attack", []),
           "index": index, "index_doc_count": es.request("GET", f"/{index}/_count")["count"],
           **meta, "queries": []}
    all_ok = True
    print(f"\n{hunt['id']}  {hunt['title']}")
    for q in hunt["queries"]:
        body = {"size": MAX_EVENTS, "track_total_hits": True,
                "query": {"query_string": {"query": q["lucene"]}}}
        if fields:
            body["_source"] = fields
        if sort_field:
            body["sort"] = [{sort_field: "asc"}]
        resp = es.request("POST", f"/{index}/_search", body)
        hits = resp["hits"]["total"]["value"]
        ok, rule = check(q.get("expect"), hits)
        all_ok &= ok
        record = {"name": q["name"], "purpose": q.get("purpose"), "lucene": q["lucene"],
                  "hits": hits, "expectation": rule, "passed": ok,
                  "events": [h["_source"] for h in resp["hits"]["hits"]]}
        if q.get("stack"):
            record["stack"] = stack(es, index, q["lucene"], q["stack"])
        out["queries"].append(record)
        print(f"  [{'PASS' if ok else 'FAIL'}] {q['name']}: {hits} hits ({rule})")
    out["passed"] = all_ok
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    with open(os.path.join(ROOT, "results", f"{hunt['id']}.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    return out


def write_step_summary(results):
    """Render a table on the GitHub Actions run page, when running in CI."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = ["## Hunt validation", "", "| Hunt | Query | Hits | Expectation | Result |",
             "| --- | --- | --- | --- | --- |"]
    for r in results:
        for q in r["queries"]:
            lines.append(f"| {r['id']} | {q['name']} | {q['hits']} | {q['expectation']} | "
                         f"{'PASS' if q['passed'] else 'FAIL'} |")
    with open(path, "a") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    wanted = set(sys.argv[1:])
    es = ES()
    info = es.info()
    meta = {
        "run_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ran_on": os.environ.get("HUNT_RUN_LABEL") or socket.gethostname(),
        "elasticsearch_version": info["version"]["number"],
        "cluster_name": info.get("cluster_name"),
        "repo_commit": git_sha(),
    }
    paths = sorted(glob.glob(os.path.join(ROOT, "hunts", "H-*", "hunt.yml")))
    results = []
    for p in paths:
        hunt_id = os.path.basename(os.path.dirname(p))[:5]
        if wanted and hunt_id not in wanted:
            continue
        results.append(run_hunt(es, p, meta))
    write_step_summary(results)
    failed = [r["id"] for r in results if not r["passed"]]
    print(f"\n{len(results)} hunt(s) run, {len(failed)} failed {failed if failed else ''}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
