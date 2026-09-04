"""
Detection Rules — External Resource Tracker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects REAL external (cross-origin) resource references
parsed from the actual HTML returned by a single, real HTTP GET request
to a target URL you provide (see app/security_engine). No external
resources are ever fetched by this tool, and no sample HTML is ever
generated — every finding is derived from the real page markup.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

EXCESSIVE_ORIGIN_THRESHOLD = 8


def _external_resources(response, tag=None):
    resources = [r for r in (response.get("resources") or []) if r["is_external"]]
    if tag:
        return [r for r in resources if r["tag"] == tag]
    return resources


def rule_external_script_missing_sri(response):
    """ERT-001: An external (cross-origin) <script> tag has no Subresource
    Integrity (integrity attribute). Without SRI, if the third-party host
    or CDN is ever compromised, the modified script executes in your
    page's full security context with no browser-side integrity check."""
    findings = []
    for r in _external_resources(response, "script"):
        if not r["integrity"]:
            findings.append({
                "rule_id": "ERT-001",
                "rule_name": "External Script Missing Subresource Integrity",
                "severity": SEVERITY_HIGH,
                "description": (
                    f"An external script from {r['origin']} "
                    f"({r['resolved_url']}) on {response['url']} has no "
                    f"integrity attribute. Without SRI, a compromise of "
                    f"that origin/CDN would execute unmodified in your "
                    f"page's security context."
                ),
            })
    return findings


def rule_external_stylesheet_missing_sri(response):
    """ERT-002: An external (cross-origin) stylesheet <link> has no
    Subresource Integrity (integrity attribute). Malicious CSS can be used
    for data exfiltration (CSS injection/attribute selectors) and UI
    redressing, so an unverified external stylesheet is a real risk."""
    findings = []
    for r in _external_resources(response, "link"):
        if not r["integrity"]:
            findings.append({
                "rule_id": "ERT-002",
                "rule_name": "External Stylesheet Missing Subresource Integrity",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"An external stylesheet from {r['origin']} "
                    f"({r['resolved_url']}) on {response['url']} has no "
                    f"integrity attribute."
                ),
            })
    return findings


def rule_external_script_over_http(response):
    """ERT-003: An external <script> tag is loaded over plain HTTP. This
    is a critical mixed-content / man-in-the-middle risk: any
    network-position attacker can rewrite the script before it reaches
    the browser, gaining full script execution in your page."""
    findings = []
    for r in _external_resources(response, "script"):
        if r["scheme"] == "http":
            findings.append({
                "rule_id": "ERT-003",
                "rule_name": "External Script Loaded Over Plain HTTP",
                "severity": SEVERITY_CRITICAL,
                "description": (
                    f"An external script is loaded over plain HTTP from "
                    f"{r['resolved_url']} on {response['url']}. A "
                    f"network-position attacker could rewrite this script "
                    f"before it reaches the browser."
                ),
            })
    return findings


def rule_cross_origin_iframe_missing_sandbox(response):
    """ERT-004: An <iframe> embeds cross-origin content with no sandbox
    attribute. The sandbox attribute restricts what embedded content can
    do (script execution, top-level navigation, popups, form submission,
    etc.); without it, a compromised or malicious embed has the full
    range of iframe capabilities."""
    findings = []
    for r in _external_resources(response, "iframe"):
        if r["sandbox"] is None:
            findings.append({
                "rule_id": "ERT-004",
                "rule_name": "Cross-Origin iframe Missing sandbox Attribute",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"A cross-origin iframe embedding {r['resolved_url']} "
                    f"on {response['url']} has no sandbox attribute, "
                    f"granting it the full range of iframe capabilities."
                ),
            })
    return findings


def rule_excessive_external_origins(response):
    """ERT-005 (informational): The page loads resources from an unusually
    high number of distinct external origins. Each additional third-party
    origin is an additional supply-chain trust dependency; a large count
    is worth reviewing even if no single resource is individually
    misconfigured."""
    origins = response.get("external_origins") or []
    if len(origins) > EXCESSIVE_ORIGIN_THRESHOLD:
        return {
            "rule_id": "ERT-005",
            "rule_name": "Excessive Number of Distinct External Origins",
            "severity": SEVERITY_LOW,
            "description": (
                f"{response['url']} loads resources from {len(origins)} "
                f"distinct external origins (threshold: "
                f"{EXCESSIVE_ORIGIN_THRESHOLD}): {', '.join(origins[:10])}"
                f"{'...' if len(origins) > 10 else ''}. Each additional "
                f"origin is an additional supply-chain trust dependency."
            ),
        }
    return None


def rule_crossorigin_attribute_without_integrity(response):
    """ERT-006 (informational): A resource sets crossorigin="anonymous"/
    "use-credentials" (requesting CORS) but has no integrity attribute.
    Setting crossorigin without integrity gets none of SRI's protection
    while still opting into a CORS request — usually a sign SRI was
    intended but not completed."""
    findings = []
    for r in _external_resources(response):
        if r["tag"] in ("script", "link") and r["crossorigin"] and not r["integrity"]:
            findings.append({
                "rule_id": "ERT-006",
                "rule_name": "crossorigin Attribute Set Without integrity",
                "severity": SEVERITY_LOW,
                "description": (
                    f"A {r['tag']} tag referencing {r['resolved_url']} on "
                    f"{response['url']} sets crossorigin=\"{r['crossorigin']}\" "
                    f"but has no integrity attribute — SRI was likely "
                    f"intended but not completed."
                ),
            })
    return findings


ALL_RULES = [
    rule_external_script_missing_sri,
    rule_external_stylesheet_missing_sri,
    rule_external_script_over_http,
    rule_cross_origin_iframe_missing_sandbox,
    rule_excessive_external_origins,
    rule_crossorigin_attribute_without_integrity,
]
