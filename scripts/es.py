"""Minimal Elasticsearch client using only the Python standard library.

Connection settings come from environment variables so nothing secret
lives in the repo:

  ES_URL        default http://localhost:9200 (Grace over the SSH tunnel)
  ES_USER       basic-auth username (optional)
  ES_PASS       basic-auth password (optional)
  ES_API_KEY    base64 API key; used instead of user/pass when set (optional)
  ES_CA_CERT    path to the cluster's CA certificate for https (preferred)
  ES_INSECURE   set to 1 to skip TLS verification (lab only, never prod)
"""

import base64
import json
import os
import ssl
import urllib.error
import urllib.request


class ES:
    def __init__(self):
        self.url = os.environ.get("ES_URL", "http://localhost:9200").rstrip("/")
        self.headers = {"Content-Type": "application/json"}
        api_key = os.environ.get("ES_API_KEY")
        user, pw = os.environ.get("ES_USER"), os.environ.get("ES_PASS")
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"
        elif user and pw:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"

        self.ctx = None
        if self.url.startswith("https"):
            ca = os.environ.get("ES_CA_CERT")
            if ca:
                self.ctx = ssl.create_default_context(cafile=ca)
            elif os.environ.get("ES_INSECURE") == "1":
                self.ctx = ssl._create_unverified_context()

    def request(self, method, path, body=None, content_type=None):
        data = None
        headers = dict(self.headers)
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=300) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")
            raise RuntimeError(f"{method} {path} -> HTTP {err.code}: {detail[:500]}") from None

    def info(self):
        return self.request("GET", "/")
