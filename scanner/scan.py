'''
Trivy and Checkov create a lot of duplicates, this script is a quick poc for deduplication biased towards Trivy findings.
'''

import json
import pandas as pd

DEDUP_MAP = {
    # (resource_type_prefix, keyword) -> deduped issue name
    ("aws_security_group", "ssh"):        "unrestricted_ssh_ingress",
    ("aws_security_group", "0.0.0.0:0 to port 22"): "unrestricted_ssh_ingress",
    ("aws_security_group", "description"): "missing_sg_description",
}

OWASP_MAP = {
    "iam": "OWASP AO1:2025 - Broken Access Control",
    "encrypt": "OWASP A04:2025 - Cryptographic Failures",
    "logging": "OWASP A09:2025 - Security Logging and Alerting Failures"
}

def parse_results(trivy_path: str, checkov_path: str):
    with open(trivy_path) as trivy_file:
      trivy_results = json.load(trivy_file)
    with open(checkov_path) as checkov_file:
      checkov_results = json.load(checkov_file)
    results = deduplicate_results(trivy_results, checkov_results)
    with open("security_report.md", "w") as f: f.write(results_to_markdown(results))

def deduplicate_results(trivy_results: dict, checkov_results: dict) -> dict:
    deduped_issues = dict() # use uniqueness of dict keys to dedupe, after normalization of keys Trivy may overwrite Checkov findings

    # checkov first, since it doesn't have a resolution field and is often missing severity
    # we want to overwrite duplicate findings with the Trivy entry that DOES have resolution details
    for finding in checkov_results["results"]["failed_checks"]:
        key = normalize_key(finding["resource"], finding["check_name"])
        deduped_issues[key] = (finding ["severity"], map_to_owasp(key), "checkov", finding["check_id"], None, finding["file_line_range"][0], finding["file_line_range"][1])

    for target in trivy_results["Results"]:
        if target["MisconfSummary"]["Failures"] > 0:
            for finding in target["Misconfigurations"]:
                key = normalize_key(finding["CauseMetadata"]["Resource"], finding["Title"])
                deduped_issues[key] = (finding["Severity"], map_to_owasp(key), "trivy", finding["ID"], finding["Resolution"], finding["CauseMetadata"]["StartLine"], finding["CauseMetadata"]["EndLine"])

    return deduped_issues

def normalize_key(resource: str, title: str) -> str:
    title_lower = title.lower()
    rtype = resource.split(".")[0]
    for (rprefix, keyword), deduped in DEDUP_MAP.items():
        if rprefix == rtype and keyword in title_lower:
            return f"{resource}::{deduped}"
    return f"{resource}::{title_lower}"  # fallback: no dedup

def map_to_owasp(issue_name: str) -> str:
    for keyword, owasp in OWASP_MAP.items():
        if keyword in issue_name:
            return owasp
    return "A02:2025 - Security Misconfiguration" # default category

def results_to_markdown(deduped_results: dict) -> str:
    df = pd.DataFrame.from_dict(deduped_results, orient='index', columns=["Severity", "OWASP Category", "Source", "Check ID", "Resolution", "Start Line", "End Line"])
    df.index.name = "Resource::Issue"
    markdown_table = df.to_markdown()
    return markdown_table

if __name__ == "__main__":
    parse_results("trivy-results.json", "checkov-results/results_json.json")