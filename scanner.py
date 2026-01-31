import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS and data injection attacks",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Prevents MIME-sniffing",
    "Strict-Transport-Security": "Enforces HTTPS",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts browser features"
}

def scan_headers(url):
    findings = []

    try:
        response = requests.get(url, timeout=5)

        print(f"\nScanning {url}")
        print("-" * 40)

        for header, description in SECURITY_HEADERS.items():
            if header in response.headers:
                print(f"[OK] {header}")
            else:
                print(f"[MISSING] {header}")
                findings.append(f"{header} missing – {description}")

        return findings

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return []

def generate_report(findings):
    with open("report.txt", "w") as report:
        report.write("HTTP Security Header Scan Report\n")
        report.write("=" * 35 + "\n\n")

        if not findings:
            report.write("No missing security headers detected.\n")
        else:
            for finding in findings:
                report.write(f"- {finding}\n")

if __name__ == "__main__":
    target = input("Enter target URL (e.g. https://example.com): ")
    results = scan_headers(target)
    generate_report(results)
    print("\nScan complete. Report saved to report.txt")

