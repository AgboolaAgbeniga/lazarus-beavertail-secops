# 🛡️ Lazarus / BeaverTail SecOps Tool Suite

This repository contains an open-source, zero-dependency Python tool suite designed to detect, remediate, and prevent the **Lazarus Group / BeaverTail ("Contagious Interview")** supply-chain malware across your GitHub estate.

## 🚨 The Threat
North Korean state-sponsored threat actors are targeting developers with fake coding assessments. When you clone their rigged repositories (often disguised as React, Next.js, or Vite projects), malware executes on your machine.
They achieve this by hiding malicious JavaScript payloads in:
1. Obfuscated configuration files (`tailwind.config.js`, `vite.config.js`).
2. Fake web font files (`.woff`, `.woff2`).
3. Weaponized VS Code tasks (`.vscode/tasks.json`) that trigger background execution automatically.

## 🛠️ The Tools

This suite includes three core components:

1. **`lazarus_scanner.py`**: A highly advanced local scanner that inspects file headers, deep whitespace runs, hidden `eval()` blocks, fake `.woff` font payloads, and malicious `.vscode/tasks.json` triggers.
2. **`bulk_lazarus_secops.py`**: An enterprise-grade automation tool that securely clones your entire GitHub estate, scans every repository, injects CI/CD workflows, and enforces branch protection rules in bulk.
3. **`workflows/lazarus-scan.yml`**: A GitHub Actions CI pipeline configuration that blocks any infected code from being merged in the future.

## 🚀 Quick Start

### 1. Scan a Single Local Repository
Download `lazarus_scanner.py` and run it against any suspicious directory:
```bash
python lazarus_scanner.py /path/to/suspect/repo
```
*To attempt automatic malware removal from config files, add the `--fix` flag.*

### 2. Audit Your Entire GitHub Estate
Download `bulk_lazarus_secops.py` and `lazarus_scanner.py`.
Create a `.env` file containing your GitHub Personal Access Token:
```env
GITHUB_TOKEN=github_pat_your_token_here
```
Run an estate-wide scan:
```bash
python bulk_lazarus_secops.py --mode scan-only
```
This will clone all your repositories locally into a temporary directory, scan them, and generate a comprehensive `bulk_secops_report.json`.

### 3. Inject Automated CI Protection & Branch Rules
To automatically inject the continuous integration scanner into every repository you own and enforce strict branch protection (preventing force pushes and mandating CI checks):
```bash
python bulk_lazarus_secops.py --mode commit-ci --protect-branches
```
*(Note: Automated branch protection requires the `Administration: Read and Write` scope on your GitHub token).*

## 📖 Full Tutorial
If you've been infected and need to know how to permanently erase the malware from your Git history (using `git filter-repo`), please read the [Full Remediation Guide](https://github.com/AgboolaAgbeniga/lazarus-beavertail-secops/wiki) (or follow the provided tutorial).

## 🤝 Contribution
Contributions to improve detection rules or add support for additional languages/frameworks are welcome.

*Stay vigilant. Never trust unsolicited coding assessments.*
