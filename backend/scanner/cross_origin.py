_CROSS_ORIGIN_HEADERS = {
    "Cross-Origin-Opener-Policy": {
        "deduction": 2,
        "severity": "minor",
        "explanation": "COOP prevents other sites from getting a window reference to this page, blocking cross-origin attacks like Spectre and clickjacking via window handles.",
        "business_impact": "Pages opened as pop-ups retain a window reference to your page, enabling cross-origin DOM probing and Spectre-class timing attacks.",
        "fix": "Cross-Origin-Opener-Policy: same-origin",
        "weak_values": ["unsafe-none"],
    },
    "Cross-Origin-Embedder-Policy": {
        "deduction": 2,
        "severity": "minor",
        "explanation": "COEP prevents the page from loading cross-origin resources that don't grant explicit permission, required to enable SharedArrayBuffer and high-resolution timers.",
        "business_impact": "Cross-origin isolation is disabled — your page cannot use SharedArrayBuffer and remains exposed to Spectre hardware timing side-channels.",
        "fix": "Cross-Origin-Embedder-Policy: require-corp",
        "weak_values": ["unsafe-none"],
    },
    "Cross-Origin-Resource-Policy": {
        "deduction": 2,
        "severity": "minor",
        "explanation": "CORP tells browsers to block no-cors cross-origin requests to this resource, preventing cross-origin data leaks via <img> or <script> tags.",
        "business_impact": "Other sites can embed your resources and infer their content through timing side-channel measurements, leaking sensitive data.",
        "fix": "Cross-Origin-Resource-Policy: same-origin",
        "weak_values": ["cross-origin"],
    },
}


def scan_cross_origin(response) -> dict:
    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    result = {}
    total_deduction = 0
    issues = 0

    for header_name, meta in _CROSS_ORIGIN_HEADERS.items():
        key = header_name.lower()
        value = resp_headers.get(key)

        if value is None:
            status = "missing"
            deduction = meta["deduction"]
            issues += 1
        elif value.strip().lower() in [w.lower() for w in meta["weak_values"]]:
            status = "weak"
            deduction = 1
            issues += 1
        else:
            status = "good"
            deduction = 0

        total_deduction += deduction
        result[header_name] = {
            "present": value is not None,
            "value": value,
            "status": status,
            "explanation": meta["explanation"],
            "business_impact": meta.get("business_impact", "") if status != "good" else "",
            "fix": meta["fix"] if status != "good" else None,
            "severity": meta["severity"],
            "deduction": deduction,
        }

    if issues == 0:
        summary = "All cross-origin isolation headers present."
    elif issues == 1:
        summary = "1 cross-origin isolation header missing or weak."
    else:
        summary = f"{issues} cross-origin isolation headers missing or weak."

    return {
        "headers": result,
        "total_deduction": total_deduction,
        "summary": summary,
    }
