"""
Security Engine — External Resource Tracker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Performs a REAL, live HTTP GET request to a target URL you provide,
parses the ACTUAL returned HTML with BeautifulSoup, and extracts every
real external (cross-origin) resource reference: <script src>, <link
rel="stylesheet" href>, and <iframe src>. Nothing is simulated: if the
target is unreachable, that is reported as a real error, not silently
faked.

SAFETY: This engine only ever issues a single, standard, non-destructive
GET request per scan, to the page itself. It never fetches any of the
discovered external resources — it only reads and parses the HTML that
was already returned by the single GET request.
"""
import time
from urllib.parse import urlsplit, urljoin

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "ExternalResourceTracker/1.0 (+https://github.com/mrshrivasta; educational security tool)"


def _resource_entry(tag_name, raw_url, page_url, page_origin, extra):
    resolved = urljoin(page_url, raw_url)
    parts = urlsplit(resolved)
    origin = f"{parts.scheme}://{parts.netloc}" if parts.netloc else page_origin
    entry = {
        "tag": tag_name,
        "raw_url": raw_url,
        "resolved_url": resolved,
        "scheme": parts.scheme,
        "origin": origin,
        "is_external": (origin != page_origin) and bool(parts.netloc),
    }
    entry.update(extra)
    return entry


def _extract_resources(html, page_url):
    soup = BeautifulSoup(html or "", "html.parser")
    page_origin = "{0.scheme}://{0.netloc}".format(urlsplit(page_url))
    resources = []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if not src:
            continue
        resources.append(_resource_entry("script", src, page_url, page_origin, {
            "integrity": tag.get("integrity") or "",
            "crossorigin": tag.get("crossorigin") or "",
            "sandbox": None,
        }))

    for tag in soup.find_all("link"):
        rel = " ".join(tag.get("rel") or []).lower()
        href = tag.get("href")
        if not href or "stylesheet" not in rel:
            continue
        resources.append(_resource_entry("link", href, page_url, page_origin, {
            "integrity": tag.get("integrity") or "",
            "crossorigin": tag.get("crossorigin") or "",
            "sandbox": None,
        }))

    for tag in soup.find_all("iframe"):
        src = tag.get("src")
        if not src:
            continue
        resources.append(_resource_entry("iframe", src, page_url, page_origin, {
            "integrity": "",
            "crossorigin": "",
            "sandbox": tag.get("sandbox"),
        }))

    return resources


class ScanEngine:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, verify_tls=True):
        self.target_url = target_url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.errors_count = 0

    def _fetch(self):
        headers = {"User-Agent": DEFAULT_USER_AGENT}
        resp = requests.get(
            self.target_url, headers=headers, timeout=self.timeout,
            verify=self.verify_tls, allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        resources = _extract_resources(resp.text, resp.url)
        external_origins = sorted({r["origin"] for r in resources if r["is_external"]})
        return {
            "url": resp.url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "headers_lower": headers_lower,
            "resources": resources,
            "external_origins": external_origins,
            "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
        }

    def run(self):
        from app.detection_rules import ALL_RULES
        start = time.time()
        findings = []
        response = None
        try:
            response = self._fetch()
            for rule in ALL_RULES:
                try:
                    result = rule(response)
                except Exception:
                    self.errors_count += 1
                    continue
                if not result:
                    continue
                result_list = result if isinstance(result, list) else [result]
                for item in result_list:
                    item["file_path"] = response["url"]
                    item["permissions_octal"] = str(response["status_code"])
                    item["owner_uid"] = None
                    item["owner_gid"] = None
                    findings.append(item)
        except requests.exceptions.RequestException as exc:
            self.errors_count += 1
            findings.append({
                "rule_id": "ERT-000",
                "rule_name": "Target Unreachable",
                "severity": "low",
                "description": f"Could not reach {self.target_url}: {exc}",
                "file_path": self.target_url,
                "permissions_octal": "-",
                "owner_uid": None,
                "owner_gid": None,
            })

        elapsed = time.time() - start
        return {
            "files_scanned": 1 if response else 0,
            "dirs_scanned": len(response["resources"]) if response else 0,
            "errors_count": self.errors_count,
            "response": response,
            "findings": findings,
            "elapsed_seconds": round(elapsed, 3),
        }
