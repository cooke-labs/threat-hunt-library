#!/usr/bin/env python3
"""Bulk-load an OTRF Security-Datasets JSON-lines file into Elasticsearch.

Reads the .json file directly, or straight out of the .zip it ships in.
Every string field is mapped as text (for search) plus .keyword (for exact
match and stacking/aggregation), so hunt queries behave the same on every
machine that loads the data with this script.

Usage:
  python3 scripts/load_otrf.py <file.json|file.zip> --index otrf-apt29-day1 [--recreate]
"""

import argparse
import io
import json
import sys
import zipfile

from es import ES

BATCH = 2000

INDEX_BODY = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "index.mapping.total_fields.limit": 5000,
        # A field holding a number in one event and "0x..." in another must not
        # reject the whole event; the bad value is skipped, the event is kept.
        "index.mapping.ignore_malformed": True,
    },
    "mappings": {
        "date_detection": False,
        "numeric_detection": False,
        "dynamic_templates": [
            {
                "strings": {
                    "match_mapping_type": "string",
                    "mapping": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword", "ignore_above": 4096}},
                    },
                }
            }
        ],
        "properties": {"@timestamp": {"type": "date"}},
    },
}


def iter_lines(path):
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    with zf.open(name) as fh:
                        for line in io.TextIOWrapper(fh, encoding="utf-8"):
                            yield line
    else:
        with open(path, encoding="utf-8") as fh:
            yield from fh


def flush(es, index, batch, stats):
    body = "".join(batch).encode()
    resp = es.request("POST", f"/{index}/_bulk", body, content_type="application/x-ndjson")
    for item in resp.get("items", []):
        result = item.get("index", {})
        if result.get("error"):
            stats["errors"] += 1
            if stats["errors"] <= 5:
                print(f"  rejected: {json.dumps(result['error'])[:300]}", file=sys.stderr)
        else:
            stats["indexed"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--index", required=True)
    ap.add_argument("--recreate", action="store_true", help="delete the index first if it exists")
    args = ap.parse_args()

    es = ES()
    print(f"Elasticsearch {es.info()['version']['number']} at {es.url}")

    if args.recreate:
        try:
            es.request("DELETE", f"/{args.index}")
            print(f"Deleted existing index {args.index}")
        except RuntimeError:
            pass
    es.request("PUT", f"/{args.index}", INDEX_BODY)

    stats = {"read": 0, "indexed": 0, "errors": 0}
    batch = []
    action = json.dumps({"index": {}}) + "\n"
    for line in iter_lines(args.path):
        line = line.strip()
        if not line:
            continue
        stats["read"] += 1
        batch.append(action)
        batch.append(line + "\n")
        if len(batch) >= BATCH * 2:
            flush(es, args.index, batch, stats)
            batch = []
            if stats["read"] % 20000 == 0:
                print(f"  {stats['read']:,} events read")
    if batch:
        flush(es, args.index, batch, stats)

    es.request("POST", f"/{args.index}/_refresh")
    count = es.request("GET", f"/{args.index}/_count")["count"]
    print(f"Read {stats['read']:,} | indexed {stats['indexed']:,} | rejected {stats['errors']:,} | "
          f"index now holds {count:,}")
    if stats["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
