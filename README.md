# Cloud IAM Entitlement Audit

**IBM SkillsBuild Cyber Security 2026 — BharatCares**  
**Author:** Gaurav Kalra

---

## 📌 Project Description

A Python-based security audit tool that uses **Checkov** (a static analysis engine for Infrastructure as Code) and **Terraform** configuration scripts to automatically detect cloud security misconfigurations, with a focus on:

- 🪣 **Exposed S3 buckets** — public-read ACLs, missing encryption, disabled versioning
- 🔑 **Exposed IAM access keys** — credentials hard-coded or provisioned via Terraform
- ⚠️ **Overly permissive IAM policies** — wildcard (`*`) actions and resources
- 🌐 **Open security groups** — unrestricted inbound access from `0.0.0.0/0`

The tool follows **shift-left security** and **policy-as-code** principles, making it suitable for integration into CI/CD pipelines.

---

## 🗂️ Project Files

| File | Description |
|------|-------------|
| `GauravKalra_CloudIAMAudit.py` | Main Python source file — audit engine, Terraform generator, Checkov runner |
| `requirements.txt` | Python dependencies |
| `GauravKalra_ProjectReport.docx` | Full project report (Word format) |
| `README.md` | This file |

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3.10+ | Core scripting and automation |
| [Checkov 3.x](https://www.checkov.io/) | Static analysis of Terraform / IaC files |
| Terraform (HCL) | Infrastructure as Code definitions to audit |
| Amazon Web Services (AWS) | Target cloud provider (S3, IAM, Security Groups) |
| boto3 *(optional)* | Live AWS resource checks |
| JSON | Structured audit report output |

---

## ⚙️ Setup & Run Instructions

### Prerequisites

- Python 3.10 or higher
- pip

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/cloud-iam-entitlement-audit.git
cd cloud-iam-entitlement-audit
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the default audit

Generates a sample Terraform file with intentional misconfigurations and scans it:

```bash
python GauravKalra_CloudIAMAudit.py
```

### 4. Audit an existing Terraform file

```bash
python GauravKalra_CloudIAMAudit.py --tf-file path/to/your/main.tf
```

### 5. Specify custom output directories

```bash
python GauravKalra_CloudIAMAudit.py --tf-dir ./terraform --report-dir ./reports
```

---

## 📁 Output

After a scan, the following files are created:

```
terraform_configs/
└── main.tf                    ← Auto-generated sample Terraform config

audit_reports/
├── checkov_results.json       ← Raw Checkov scan output
└── audit_report.json          ← Structured final report with timestamp & findings
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed — no findings |
| `1` | One or more security checks failed |

> The exit code makes this tool usable as a **CI/CD pipeline gate** to block deployments with security issues.

---

## 🔍 Security Checks Performed

| Checkov Check ID | Resource | Misconfiguration | Severity |
|------------------|----------|-----------------|----------|
| CKV_AWS_20 | `aws_s3_bucket` | Public-read ACL | HIGH |
| CKV_AWS_21 | `aws_s3_bucket` | Versioning disabled | MEDIUM |
| CKV_AWS_19 | `aws_s3_bucket` | No server-side encryption | HIGH |
| CKV_AWS_40 | `aws_iam_policy` | Wildcard actions `*` | CRITICAL |
| CKV_AWS_25 | `aws_security_group` | All ports open to `0.0.0.0/0` | HIGH |
| CKV_AWS_4 | `aws_iam_access_key` | Access key in Terraform | HIGH |

---

## 📊 Dataset / Sample Configuration

The project generates its own sample Terraform configuration at runtime (`terraform_configs/main.tf`). This file contains:

- ❌ **Bad resources** — intentionally misconfigured to trigger Checkov findings
- ✅ **Good resources** — correctly configured to demonstrate passing checks

No external dataset is required. To audit a real infrastructure, pass your own `.tf` file using `--tf-file`.

---

## 🔐 Security Concepts Demonstrated

- **Principle of Least Privilege (PoLP)**
- **Policy as Code (PaC)**
- **Shift-Left Security** in DevSecOps
- **CIS AWS Foundations Benchmark** alignment
- **Data exposure prevention** (S3 bucket ACL and encryption)
- **Credential management** best practices

---

## 🚀 Future Enhancements

- Live AWS auditing via `boto3`
- Multi-cloud support (Azure, GCP)
- HTML/PDF report generation
- GitHub Actions CI/CD integration
- Slack/email alerts for CRITICAL findings

---

## 📄 License

This project was created for educational purposes as part of the **IBM SkillsBuild Cyber Security 2026** bootcamp conducted by **BharatCares**.

---

## 🙏 Acknowledgements

- [Checkov by Bridgecrew / Prisma Cloud](https://www.checkov.io/)
- [Terraform by HashiCorp](https://www.terraform.io/)
- [IBM SkillsBuild](https://skillsbuild.org/)
- BharatCares for organising the bootcamp
