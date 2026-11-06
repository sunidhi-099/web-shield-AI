import requests


def check_security_headers(url):
    findings = []

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers

        security_headers = {
            "Content-Security-Policy":
                "Helps reduce certain cross-site scripting risks.",
            "Strict-Transport-Security":
                "Tells browsers to use HTTPS for future requests.",
            "X-Content-Type-Options":
                "Helps prevent MIME-type sniffing.",
            "X-Frame-Options":
                "Helps protect against clickjacking."
        }

        for header, explanation in security_headers.items():
            if header not in headers:
                findings.append({
                    "title": f"Missing {header}",
                    "severity": "Medium",
                    "evidence": f"The response did not include {header}.",
                    "recommendation": explanation
                })

        return {
            "status": response.status_code,
            "final_url": response.url,
            "findings": findings,
            "error": None
        }

    except requests.RequestException as error:
        return {
            "status": None,
            "final_url": url,
            "findings": [],
            "error": str(error)
        }