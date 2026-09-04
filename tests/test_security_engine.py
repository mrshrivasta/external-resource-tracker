"""Tests for the External Resource Tracker's Security Engine and rules.

Rule-level tests use synthetic response dicts with pre-parsed 'resources'
lists (no network calls). The engine-level tests spin up a REAL local HTTP
server (Python's http.server, on an ephemeral localhost port) serving REAL
HTML with external resource references, and perform a REAL HTTP request +
REAL BeautifulSoup parse against it via the actual ScanEngine code path —
genuine end-to-end testing without touching any third-party site. No
discovered external resource is ever fetched by this tool.
"""
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, _extract_resources
from app.detection_rules import (
    rule_external_script_missing_sri,
    rule_external_stylesheet_missing_sri,
    rule_external_script_over_http,
    rule_cross_origin_iframe_missing_sandbox,
    rule_excessive_external_origins,
    rule_crossorigin_attribute_without_integrity,
)


def resp(url="https://example.com/", resources=None, external_origins=None):
    resources = resources or []
    return {
        "url": url, "status_code": 200, "resources": resources,
        "external_origins": external_origins if external_origins is not None else sorted({r["origin"] for r in resources if r["is_external"]}),
    }


def resource(tag="script", resolved_url="https://cdn.example/lib.js", scheme="https",
             origin="https://cdn.example", is_external=True, integrity="", crossorigin="", sandbox=None):
    return {
        "tag": tag, "raw_url": resolved_url, "resolved_url": resolved_url, "scheme": scheme,
        "origin": origin, "is_external": is_external, "integrity": integrity,
        "crossorigin": crossorigin, "sandbox": sandbox,
    }


def test_external_script_missing_sri_flagged():
    result = rule_external_script_missing_sri(resp(resources=[resource(integrity="")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "ERT-001"


def test_external_script_with_sri_not_flagged():
    result = rule_external_script_missing_sri(resp(resources=[resource(integrity="sha384-abc")]))
    assert result == []


def test_external_stylesheet_missing_sri_flagged():
    result = rule_external_stylesheet_missing_sri(resp(resources=[resource(tag="link", integrity="")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "ERT-002"


def test_external_script_over_http_flagged_critical():
    result = rule_external_script_over_http(resp(resources=[resource(scheme="http", resolved_url="http://cdn.example/lib.js")]))
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_external_script_over_https_not_flagged():
    result = rule_external_script_over_http(resp(resources=[resource(scheme="https")]))
    assert result == []


def test_iframe_missing_sandbox_flagged():
    result = rule_cross_origin_iframe_missing_sandbox(resp(resources=[resource(tag="iframe", sandbox=None)]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "ERT-004"


def test_iframe_with_sandbox_not_flagged():
    result = rule_cross_origin_iframe_missing_sandbox(resp(resources=[resource(tag="iframe", sandbox="")]))
    assert result == []


def test_excessive_external_origins_flagged():
    origins = [f"https://cdn{i}.example" for i in range(10)]
    result = rule_excessive_external_origins(resp(external_origins=origins))
    assert result is not None
    assert result["rule_id"] == "ERT-005"


def test_few_external_origins_not_flagged():
    result = rule_excessive_external_origins(resp(external_origins=["https://cdn.example"]))
    assert result is None


def test_crossorigin_without_integrity_flagged():
    result = rule_crossorigin_attribute_without_integrity(resp(resources=[resource(crossorigin="anonymous", integrity="")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "ERT-006"


def test_crossorigin_with_integrity_not_flagged():
    result = rule_crossorigin_attribute_without_integrity(resp(resources=[resource(crossorigin="anonymous", integrity="sha384-abc")]))
    assert result == []


def test_extract_resources_from_real_html():
    html = """
    <html><head>
      <script src="https://cdn.example/lib.js"></script>
      <link rel="stylesheet" href="https://cdn.example/style.css">
    </head><body>
      <iframe src="https://widget.example/embed"></iframe>
      <script src="/local/app.js"></script>
    </body></html>
    """
    resources = _extract_resources(html, "https://example.com/page")
    assert len(resources) == 4
    external = [r for r in resources if r["is_external"]]
    assert len(external) == 3
    local = [r for r in resources if not r["is_external"]]
    assert len(local) == 1


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = """
        <html><head>
          <script src="http://cdn.example.invalid/lib.js"></script>
          <link rel="stylesheet" href="https://cdn.example.invalid/style.css">
        </head><body>
          <iframe src="https://widget.example.invalid/embed"></iframe>
        </body></html>
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_real_engine_against_local_test_server():
    """Genuine end-to-end HTTP test: real request, real HTML, real parsed
    external resources, real findings — against a local server we control
    (not a third party). No discovered external resource is ever fetched."""
    server, port = _start_test_server()
    try:
        time.sleep(0.2)
        engine = ScanEngine(f"http://127.0.0.1:{port}/", timeout=5)
        result = engine.run()
        assert result["response"]["status_code"] == 200
        assert len(result["response"]["resources"]) == 3
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "ERT-001" in rule_ids  # external script missing SRI
        assert "ERT-002" in rule_ids  # external stylesheet missing SRI
        assert "ERT-003" in rule_ids  # external script over plain http
        assert "ERT-004" in rule_ids  # cross-origin iframe missing sandbox
    finally:
        server.shutdown()


def test_engine_handles_unreachable_target_gracefully():
    engine = ScanEngine("http://127.0.0.1:1/", timeout=2)
    result = engine.run()
    assert result["errors_count"] >= 1
    assert any(f["rule_id"] == "ERT-000" for f in result["findings"])
