# Results

One JSON file per hunt, written by `scripts/run_hunts.py`. Each file records when and
where it ran (`run_at_utc`, `ran_on`, `elasticsearch_version`, `repo_commit`), the index
size, and for every query: the exact Lucene string, the hit count, whether it matched the
hunt's expectation, the matching events (first 50), and any stacking counts.

Files here come from runs on my lab Elasticsearch. CI produces the same files on every
push as a downloadable artifact.
