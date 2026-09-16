#!/usr/bin/env python3
"""
Mock Iceberg REST catalog that vends storage credentials, for testing credential
renewal and internal-secret cleanup.

The local docker fixture returns neither "config" nor "storage-credentials" on
loadTable, so it never reaches the branch of GetVendedCredentials that handles
vended credentials. This server does.

Behaviour that makes the bugs observable:

  * Every loadTable returns "storage-credentials" whose prefix carries the
    request number, so a re-vend is visible through duckdb_secrets().scope
    without any access to the server from the test.
  * The vended token is stamped with an expiry in the past by default, so the
    renewal path triggers on the second read inside one transaction.
  * The table is empty (no snapshots), so a scan succeeds without any data file
    or manifest, while still vending a credential and registering a secret.
  * Commits are rejected without X-Iceberg-Access-Delegation, the way BigLake
    rejects them once a catalog is in vended-credentials mode.

Usage:
    python3 vended_credential_mock_server.py [port]
    Default port: 19140
"""

import json
import sys
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler

NAMESPACE = "vend"
TABLE = "t"

# Far enough in the past that no clock skew or expiry buffer can call it live.
EXPIRED_AT_MS = 1000000000000

TABLE_UUID = str(uuid.UUID(int=0x5EEDDB))

ENDPOINTS = [
    "GET /v1/{prefix}/namespaces",
    "POST /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}",
    "HEAD /v1/{prefix}/namespaces/{namespace}",
    "DELETE /v1/{prefix}/namespaces/{namespace}",
    "POST /v1/{prefix}/namespaces/{namespace}/properties",
    "GET /v1/{prefix}/namespaces/{namespace}/tables",
    "POST /v1/{prefix}/namespaces/{namespace}/tables",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "HEAD /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/transactions/commit",
]

state = {"load_table_requests": 0, "commits_with_delegation": 0, "commits_without": 0}


def table_metadata():
    return {
        "format-version": 2,
        "table-uuid": TABLE_UUID,
        "location": "gs://mock-warehouse/vend/t",
        "last-sequence-number": 0,
        "last-updated-ms": 1700000000000,
        "last-column-id": 1,
        "schemas": [
            {
                "type": "struct",
                "schema-id": 0,
                "fields": [{"id": 1, "name": "id", "required": False, "type": "int"}],
            }
        ],
        "current-schema-id": 0,
        "partition-specs": [{"spec-id": 0, "fields": []}],
        "default-spec-id": 0,
        "last-partition-id": 999,
        "sort-orders": [{"order-id": 0, "fields": []}],
        "default-sort-order-id": 0,
        "properties": {},
        "current-snapshot-id": -1,
        "snapshots": [],
        "snapshot-log": [],
        "metadata-log": [],
    }


def load_table_result():
    state["load_table_requests"] += 1
    n = state["load_table_requests"]
    return {
        "metadata-location": "gs://mock-warehouse/vend/t/metadata/v1.metadata.json",
        "metadata": table_metadata(),
        "storage-credentials": [
            {
                "prefix": "gs://mock-warehouse/vend-{}/".format(n),
                "config": {
                    "gcs.oauth2.token": "mock-token-{}".format(n),
                    "gcs.oauth2.token-expires-at": str(EXPIRED_AT_MS),
                },
            }
        ],
    }


class MockVendingCatalogHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _respond(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message, err_type):
        self._respond(
            code, {"error": {"message": message, "type": err_type, "code": code}}
        )

    def _has_delegation(self):
        header = self.headers.get("X-Iceberg-Access-Delegation", "")
        return "vended-credentials" in header

    def do_GET(self):
        if self.path.startswith("/v1/config"):
            self._respond(200, {"defaults": {}, "overrides": {}, "endpoints": ENDPOINTS})
        elif self.path.rstrip("/").endswith("/namespaces"):
            self._respond(200, {"namespaces": [[NAMESPACE]]})
        elif self.path.rstrip("/").endswith("/tables"):
            self._respond(
                200,
                {"identifiers": [{"namespace": [NAMESPACE], "name": TABLE}]},
            )
        elif self.path.rstrip("/").endswith("/tables/{}".format(TABLE)):
            self._respond(200, load_table_result())
        elif "/namespaces/{}".format(NAMESPACE) in self.path:
            self._respond(200, {"namespace": [NAMESPACE], "properties": {}})
        else:
            self._error(404, "not found: {}".format(self.path), "NoSuchTableException")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)

        if self.path.rstrip("/").endswith("/tables/{}".format(TABLE)) or self.path.rstrip(
            "/"
        ).endswith("/transactions/commit"):
            if not self._has_delegation():
                state["commits_without"] += 1
                self._error(
                    400,
                    "X-Iceberg-Access-Delegation header must be present and contain "
                    "`vended-credentials` when credential mode is "
                    "`CREDENTIAL_MODE_VENDED_CREDENTIALS`.",
                    "IllegalArgumentException",
                )
                return
            state["commits_with_delegation"] += 1
            self._respond(200, load_table_result())
            return

        self._respond(200, {})

    def do_DELETE(self):
        self._respond(200, {})


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19140
    HTTPServer(("127.0.0.1", port), MockVendingCatalogHandler).serve_forever()


if __name__ == "__main__":
    main()
