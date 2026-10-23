"""
Cloud IAM Entitlement Audit
IBM SkillsBuild Cyber Security 2026 — BharatCares
Author : Gaurav Kalra
Topic  : Cloud IAM Entitlement Audit — Detect exposed cloud buckets and keys
         using Checkov and Terraform script analysis.
"""

import os
import json
import subprocess
import argparse
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Colour helpers (gracefully degrade when not in a TTY)
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def _c(colour: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{colour}{text}{RESET}"
    return text


# ---------------------------------------------------------------------------
# Terraform template generator
# ---------------------------------------------------------------------------

TERRAFORM_TEMPLATE = """\
# ------------------------------------------------------------
# Sample Terraform configuration — intentionally contains
# misconfigurations so Checkov can flag them.
# DO NOT deploy this as-is.
# ------------------------------------------------------------

provider "aws" {
  region = "us-east-1"
}

# ❌  BAD: S3 bucket with public-read ACL (exposed bucket)
resource "aws_s3_bucket" "exposed_bucket" {
  bucket = "my-exposed-bucket-demo"
  acl    = "public-read"

  tags = {
    Name        = "ExposedBucket"
    Environment = "Dev"
  }
}

# ❌  BAD: S3 bucket versioning disabled
resource "aws_s3_bucket" "no_versioning" {
  bucket = "my-no-versioning-bucket"
  acl    = "private"
}

# ✅  GOOD: S3 bucket — private, versioning enabled, server-side encryption
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-demo"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name        = "SecureBucket"
    Environment = "Prod"
  }
}

# ❌  BAD: IAM user with hard-coded access key (exposed key)
resource "aws_iam_access_key" "exposed_key" {
  user = "demo-user"
}

resource "aws_iam_user" "demo_user" {
  name = "demo-user"
}

# ❌  BAD: Overly permissive IAM policy (wildcard actions + resources)
resource "aws_iam_policy" "overly_permissive" {
  name        = "OverlyPermissivePolicy"
  description = "Wildcard policy — never use in production"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = ["*"]
      }
    ]
  })
}

# ❌  BAD: Security group open to the world on all ports
resource "aws_security_group" "open_sg" {
  name        = "open-all-ports"
  description = "Allows all inbound traffic — misconfiguration demo"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅  GOOD: Security group restricted to HTTPS only
resource "aws_security_group" "restricted_sg" {
  name        = "allow-https-only"
  description = "Allows HTTPS inbound traffic only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def generate_terraform_file(output_path: Path) -> None:
    output_path.write_text(TERRAFORM_TEMPLATE, encoding="utf-8")
    print(_c(GREEN, f"[+] Terraform file written → {output_path}"))


# ---------------------------------------------------------------------------
# Checkov runner
# ---------------------------------------------------------------------------

def run_checkov(tf_file: Path, report_dir: Path) -> dict:
    """
    Run Checkov against the given Terraform file.
    Returns parsed JSON results (or an empty dict on failure).
    """
    json_output = report_dir / "checkov_results.json"
    cmd = [
        "checkov",
        "--file", str(tf_file),
        "--output", "json",
        "--output-file", str(json_output),
        "--quiet",
    ]

    print(_c(CYAN, f"\n[*] Running Checkov on {tf_file.name} …"))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Checkov exits with 1 when it finds failures — that is expected.
        if result.returncode not in (0, 1):
            print(_c(RED, f"[!] Checkov exited with code {result.returncode}"))
            if stderr:
                print(_c(RED, f"    stderr: {stderr}"))
            return {}

        # Prefer the JSON output file; fall back to stdout
        if json_output.exists():
            with json_output.open(encoding="utf-8") as fh:
                return json.load(fh)
        if stdout:
            return json.loads(stdout)

    except FileNotFoundError:
        print(_c(RED, "[!] Checkov not found. Install it with:  pip install checkov"))
    except subprocess.TimeoutExpired:
        print(_c(RED, "[!] Checkov timed out."))
    except json.JSONDecodeError as exc:
        print(_c(RED, f"[!] Failed to parse Checkov output: {exc}"))

    return {}


# ---------------------------------------------------------------------------
# Results parser & display
# ---------------------------------------------------------------------------

def _extract_checks(data: dict) -> tuple[list, list]:
    """Return (passed_checks, failed_checks) from Checkov JSON."""
    # Checkov JSON can be a list (one entry per resource type) or a single dict
    if isinstance(data, list):
        passed, failed = [], []
        for block in data:
            r = block.get("results", {})
            passed.extend(r.get("passed_checks", []))
            failed.extend(r.get("failed_checks", []))
        return passed, failed

    results = data.get("results", {})
    return (
        results.get("passed_checks", []),
        results.get("failed_checks", []),
    )


def display_results(data: dict) -> dict:
    """Pretty-print Checkov results and return a summary dict."""
    passed, failed = _extract_checks(data)

    print("\n" + "=" * 60)
    print(_c(BOLD, "  CLOUD IAM ENTITLEMENT AUDIT — RESULTS"))
    print("=" * 60)
    print(f"  Scan time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Passed    : {_c(GREEN, str(len(passed)))}")
    print(f"  Failed    : {_c(RED,   str(len(failed)))}")
    print("=" * 60)

    if failed:
        print(_c(RED, "\n[FAILED CHECKS]"))
        for chk in failed:
            chk_id   = chk.get("check_id", "N/A")
            chk_name = chk.get("check", {}).get("name", chk.get("check_id", "N/A"))
            resource = chk.get("resource", "N/A")
            file_abs = chk.get("file_abs_path", "")
            lines    = chk.get("file_line_range", [])
            print(f"\n  ✗ [{chk_id}] {chk_name}")
            print(f"    Resource : {resource}")
            if file_abs:
                print(f"    File     : {Path(file_abs).name}  lines {lines}")
            guideline = chk.get("check", {}).get("guideline", "")
            if guideline:
                print(f"    Guide    : {guideline}")

    if passed:
        print(_c(GREEN, "\n[PASSED CHECKS]"))
        for chk in passed:
            chk_id   = chk.get("check_id", "N/A")
            chk_name = chk.get("check", {}).get("name", chk.get("check_id", "N/A"))
            resource = chk.get("resource", "N/A")
            print(f"  ✓ [{chk_id}] {chk_name}  →  {resource}")

    print("\n" + "=" * 60)

    return {
        "total_passed": len(passed),
        "total_failed": len(failed),
        "failed_checks": [
            {
                "check_id": c.get("check_id"),
                "name":     c.get("check", {}).get("name", c.get("check_id")),
                "resource": c.get("resource"),
            }
            for c in failed
        ],
        "passed_checks": [
            {
                "check_id": c.get("check_id"),
                "name":     c.get("check", {}).get("name", c.get("check_id")),
                "resource": c.get("resource"),
            }
            for c in passed
        ],
    }


# ---------------------------------------------------------------------------
# Audit report writer
# ---------------------------------------------------------------------------

def save_audit_report(summary: dict, report_dir: Path) -> None:
    report_path = report_dir / "audit_report.json"
    payload = {
        "project":    "Cloud IAM Entitlement Audit",
        "author":     "Gaurav Kalra",
        "event":      "IBM SkillsBuild Cyber Security 2026 — BharatCares",
        "timestamp":  datetime.now().isoformat(),
        "summary":    summary,
    }
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(_c(GREEN, f"[+] Audit report saved → {report_path}"))


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cloud IAM Entitlement Audit — detect exposed buckets & keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python GauravKalra_CloudIAMAudit.py
  python GauravKalra_CloudIAMAudit.py --tf-dir ./terraform --report-dir ./reports
  python GauravKalra_CloudIAMAudit.py --tf-file my_infra.tf
        """,
    )
    parser.add_argument(
        "--tf-dir",
        default="terraform_configs",
        help="Directory where the sample Terraform file will be written (default: terraform_configs)",
    )
    parser.add_argument(
        "--tf-file",
        default=None,
        help="Path to an existing Terraform (.tf) file to audit instead of generating one",
    )
    parser.add_argument(
        "--report-dir",
        default="audit_reports",
        help="Directory where Checkov JSON and audit report will be saved (default: audit_reports)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Decide which Terraform file to audit
    if args.tf_file:
        tf_file = Path(args.tf_file)
        if not tf_file.exists():
            print(_c(RED, f"[!] File not found: {tf_file}"))
            sys.exit(1)
        print(_c(CYAN, f"[*] Using existing Terraform file: {tf_file}"))
    else:
        tf_dir = Path(args.tf_dir)
        tf_dir.mkdir(parents=True, exist_ok=True)
        tf_file = tf_dir / "main.tf"
        generate_terraform_file(tf_file)

    # Run Checkov
    checkov_data = run_checkov(tf_file, report_dir)

    if not checkov_data:
        print(_c(YELLOW, "[!] No Checkov results to display. Check the output above for errors."))
        sys.exit(1)

    # Display and summarise
    summary = display_results(checkov_data)

    # Save JSON audit report
    save_audit_report(summary, report_dir)

    # Exit code mirrors security posture: 0 = all clear, 1 = findings present
    sys.exit(0 if summary["total_failed"] == 0 else 1)


if __name__ == "__main__":
    main()
