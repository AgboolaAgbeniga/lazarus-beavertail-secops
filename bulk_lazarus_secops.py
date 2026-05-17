#!/usr/bin/env python3
"""
Lazarus / BeaverTail Bulk SecOps Automation Tool.

This utility automates bulk security operations across all GitHub repositories
owned by a user or organization. It provides two primary modes of operation:

1. scan-only : Bulk clones/fetches repositories and runs lazarus_scanner.py
               to audit the entire GitHub estate for configuration-injection
               malware.
2. pr-ci     : Bulk clones repositories, creates a dedicated SecOps branch,
               integrates lazarus_scanner.py and the CI workflow gate
               (.github/workflows/lazarus-scan.yml), commits, pushes, and
               automatically opens Pull Requests across all repositories.
3. commit-ci : Directly commits and pushes the CI integration to the default
               branch of each repository (useful for personal estates).

Requirements:
    - Python 3.8+ (Standard library only)
    - Git CLI installed and available in PATH
    - GitHub Personal Access Token (GITHUB_TOKEN env var) OR GitHub CLI (gh) installed/logged in.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request

# Ensure UTF-8 console encoding on Windows
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def remove_readonly(func: Any, path: str, excinfo: Any) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass

# ============================================================================
# Configuration & Constants
# ============================================================================

DEFAULT_WORK_DIR = Path("./lazarus_bulk_workdir")
DEFAULT_REPORT_FILE = Path("./bulk_secops_report.json")
PR_BRANCH_NAME = "secops/lazarus-ci-integration"
PR_TITLE = "🛡️ SecOps: Integrate Lazarus / BeaverTail Supply-Chain Security Scanner"

PR_BODY = """## 🛡️ Supply-Chain Security Gate Integration

This Pull Request integrates the **Lazarus / BeaverTail Config-Injection Scanner** into the continuous integration pipeline to protect this repository against advanced supply-chain attacks.

### 🚨 The Threat: Contagious Interview / BeaverTail
North Korean state-sponsored threat actors (Lazarus Group) have been actively targeting developers via fake job interviews and compromised packages. The attack vector injects heavily obfuscated malicious payloads into common JavaScript/TypeScript configuration files (e.g., `next.config.js`, `postcss.config.js`, `vite.config.js`).

### 🛠️ What this PR adds
1. **`lazarus_scanner.py`**: A zero-dependency, Python-based scanner designed to detect known IOCs, whitespace-padding tricks, and malicious `eval()` blocks in config files.
2. **`.github/workflows/lazarus-scan.yml`**: A GitHub Actions workflow that executes on every `push` and `pull_request`.

### 🛑 CI Gate Behavior
- If any malicious configuration injection or IOC is detected, the workflow **fails immediately (exit code 1)** and blocks deployment/merging.
- If the repository is clean, the workflow passes successfully.

---
*This Pull Request was generated automatically by the Lazarus Bulk SecOps Automation Tool.*
"""

# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class RepoInfo:
    name: str
    full_name: str
    clone_url: str
    default_branch: str
    ssh_url: str
    is_private: bool

@dataclass
class RepoResult:
    repo: RepoInfo
    status: str  # "SUCCESS", "FAILED", "THREAT_DETECTED", "SKIPPED"
    action_taken: str
    details: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    pr_url: Optional[str] = None

# ============================================================================
# GitHub API Helper
# ============================================================================

class GitHubAPI:
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Lazarus-Bulk-SecOps/1.0"
        }

    def _request(self, url: str, method: str = "GET", data: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, str]]:
        req = urllib.request.Request(url, method=method, headers=self.headers)
        if data is not None:
            req.data = json.dumps(data).encode("utf-8")
            req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req) as response:
                resp_headers = dict(response.getheaders())
                body = response.read().decode("utf-8")
                return json.loads(body) if body else None, resp_headers
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            raise RuntimeError(f"GitHub API HTTP {e.code}: {e.reason}\n{err_body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"GitHub API Connection Error: {e.reason}") from e

    def get_repositories(self, org: Optional[str] = None, user: Optional[str] = None, visibility: str = "all") -> List[RepoInfo]:
        repos: List[RepoInfo] = []
        page = 1
        per_page = 100

        while True:
            if org:
                url = f"https://api.github.com/orgs/{org}/repos?per_page={per_page}&page={page}"
            elif user:
                url = f"https://api.github.com/users/{user}/repos?per_page={per_page}&page={page}"
            else:
                url = f"https://api.github.com/user/repos?per_page={per_page}&page={page}&visibility={visibility}"

            print(f"[*] Fetching repository list (page {page})...")
            data, headers = self._request(url)
            if not data:
                break

            for item in data:
                # Skip archived or disabled repositories
                if item.get("archived") or item.get("disabled"):
                    continue

                # Filter visibility if querying /user/repos
                if visibility != "all":
                    is_priv = item.get("private", False)
                    if visibility == "public" and is_priv:
                        continue
                    if visibility == "private" and not is_priv:
                        continue

                repos.append(RepoInfo(
                    name=item["name"],
                    full_name=item["full_name"],
                    clone_url=item["clone_url"],
                    default_branch=item.get("default_branch", "main"),
                    ssh_url=item["ssh_url"],
                    is_private=item.get("private", False)
                ))

            # Check pagination
            link_header = headers.get("Link", "")
            if f'rel="next"' not in link_header:
                break
            page += 1

        return repos

    def create_pull_request(self, full_name: str, head_branch: str, base_branch: str, title: str, body: str) -> str:
        url = f"https://api.github.com/repos/{full_name}/pulls"
        payload = {
            "title": title,
            "head": head_branch,
            "base": base_branch,
            "body": body
        }
        data, _ = self._request(url, method="POST", data=payload)
        return data["html_url"]

    def protect_branch(self, full_name: str, branch: str) -> None:
        url = f"https://api.github.com/repos/{full_name}/branches/{branch}/protection"
        payload = {
            "required_status_checks": {
                "strict": True,
                "contexts": ["Lazarus / BeaverTail Config-Injection Scanner"]
            },
            "enforce_admins": True,
            "required_pull_request_reviews": {
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": False,
                "required_approving_review_count": 1
            },
            "restrictions": None
        }
        try:
            print(f"[*] {full_name}: Enabling strict branch protection on '{branch}'...")
            self._request(url, method="PUT", data=payload)
        except Exception as e:
            print(f"[!] WARNING: Could not enable branch protection for {full_name}: {e}", file=sys.stderr)

# ============================================================================
# Authentication Helper
# ============================================================================

def load_dotenv() -> None:
    env_file = Path(".env")
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    os.environ[key.strip()] = val.strip().strip("'\"")
        except OSError as e:
            print(f"[!] WARNING: Failed to read .env file: {e}", file=sys.stderr)

def get_github_token() -> str:
    # 1. Load from .env file if present
    load_dotenv()

    # 2. Check environment variable
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return token.strip()

    # 3. Try GitHub CLI
    try:
        res = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
        )
        token = res.stdout.strip()
        if token:
            return token
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print("[!] ERROR: GitHub authentication required.", file=sys.stderr)
    print("Please set the GITHUB_TOKEN in your .env file OR install/log in to the GitHub CLI (gh auth login).", file=sys.stderr)
    sys.exit(1)

# ============================================================================
# Git & File Operations
# ============================================================================

class GitWorker:
    def __init__(self, work_dir: Path, scanner_path: Path, workflow_path: Path, use_ssh: bool, dry_run: bool, protect_branches: bool = False):
        self.work_dir = work_dir
        self.scanner_path = scanner_path
        self.workflow_path = workflow_path
        self.use_ssh = use_ssh
        self.dry_run = dry_run
        self.protect_branches = protect_branches

    def _run_git(self, args: List[str], cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git"] + args,
            cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
        )

    def process_repo(self, repo: RepoInfo, mode: str, api: GitHubAPI) -> RepoResult:
        repo_dir = self.work_dir / repo.full_name
        clone_url = repo.ssh_url if self.use_ssh else repo.clone_url

        try:
            # 1. Clone or Fetch Repository
            if repo_dir.exists():
                print(f"[*] {repo.full_name}: Directory exists, cleaning up...")
                shutil.rmtree(repo_dir, onerror=remove_readonly)

            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            print(f"[*] {repo.full_name}: Cloning repository...")
            # For scan-only, shallow clone is sufficient
            depth_args = ["--depth", "1"] if mode == "scan-only" else []
            subprocess.run(
                ["git", "clone"] + depth_args + [clone_url, str(repo_dir)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
            )

            # 2. Execute Scan Mode
            if mode == "scan-only":
                return self._run_scan(repo, repo_dir)

            # 3. Execute CI Integration Modes (pr-ci or commit-ci)
            return self._run_ci_integration(repo, repo_dir, mode, api)

        except subprocess.CalledProcessError as e:
            err_msg = f"Git command failed: {e.cmd}\nStdout: {e.stdout}\nStderr: {e.stderr}"
            return RepoResult(repo=repo, status="FAILED", action_taken="clone/git_op", details=err_msg)
        except Exception as e:
            return RepoResult(repo=repo, status="FAILED", action_taken="general_exec", details=str(e))

    def _run_scan(self, repo: RepoInfo, repo_dir: Path) -> RepoResult:
        print(f"[*] {repo.full_name}: Running Lazarus scanner...")
        cmd = [sys.executable, str(self.scanner_path.resolve()), str(repo_dir), "--no-process-check", "--json"]
        
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        
        try:
            report = json.loads(res.stdout)
            file_findings = report.get("file_findings", [])
            if file_findings:
                details = f"Detected {len(file_findings)} suspicious configuration file(s)."
                return RepoResult(repo=repo, status="THREAT_DETECTED", action_taken="scan", details=details, findings=file_findings)
            else:
                return RepoResult(repo=repo, status="SUCCESS", action_taken="scan", details="No supply-chain threats detected.")
        except json.JSONDecodeError:
            return RepoResult(repo=repo, status="FAILED", action_taken="scan", details=f"Failed to parse scanner output.\nOutput: {res.stdout}\nStderr: {res.stderr}")

    def _run_ci_integration(self, repo: RepoInfo, repo_dir: Path, mode: str, api: GitHubAPI) -> RepoResult:
        # Check if already integrated
        target_workflow = repo_dir / ".github" / "workflows" / self.workflow_path.name
        target_scanner = repo_dir / self.scanner_path.name

        if target_workflow.exists() and target_scanner.exists():
            if self.protect_branches:
                api.protect_branch(repo.full_name, repo.default_branch)
            return RepoResult(repo=repo, status="SKIPPED", action_taken="check_existing", details="CI workflow and scanner already exist in repository.")

        # Determine branch
        branch = PR_BRANCH_NAME if mode == "pr-ci" else repo.default_branch

        if mode == "pr-ci":
            print(f"[*] {repo.full_name}: Creating SecOps branch '{branch}'...")
            self._run_git(["checkout", "-b", branch], cwd=repo_dir)

        # Copy Scanner Script to Repo Root
        print(f"[*] {repo.full_name}: Copying scanner and workflow files...")
        shutil.copy2(self.scanner_path, target_scanner)

        # Copy Workflow File to .github/workflows/
        target_workflow.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.workflow_path, target_workflow)

        # Stage and Commit
        self._run_git(["add", self.scanner_path.name, f".github/workflows/{self.workflow_path.name}"], cwd=repo_dir)
        
        # Check if there are changes to commit
        status_res = self._run_git(["status", "--porcelain"], cwd=repo_dir)
        if not status_res.stdout.strip():
            if self.protect_branches:
                api.protect_branch(repo.full_name, repo.default_branch)
            return RepoResult(repo=repo, status="SKIPPED", action_taken="commit", details="No changes to commit.")

        print(f"[*] {repo.full_name}: Committing changes...")
        self._run_git(["commit", "-m", PR_TITLE], cwd=repo_dir)

        if self.dry_run:
            return RepoResult(repo=repo, status="SUCCESS", action_taken="dry_run", details=f"Dry run: Files committed locally to branch '{branch}'. Push and PR skipped.")

        # Push Changes
        print(f"[*] {repo.full_name}: Pushing branch '{branch}' to remote...")
        if mode == "pr-ci":
            self._run_git(["push", "-u", "origin", branch], cwd=repo_dir)
            
            # Create Pull Request
            print(f"[*] {repo.full_name}: Opening Pull Request...")
            pr_url = api.create_pull_request(repo.full_name, branch, repo.default_branch, PR_TITLE, PR_BODY)
            if self.protect_branches:
                api.protect_branch(repo.full_name, repo.default_branch)
            return RepoResult(repo=repo, status="SUCCESS", action_taken="pr_created", details=f"Pull Request created successfully.", pr_url=pr_url)
        else:
            # commit-ci mode: push directly to default branch
            self._run_git(["push", "origin", branch], cwd=repo_dir)
            if self.protect_branches:
                api.protect_branch(repo.full_name, repo.default_branch)
            return RepoResult(repo=repo, status="SUCCESS", action_taken="direct_push", details=f"Changes pushed directly to '{branch}'.")

# ============================================================================
# Main Execution Flow
# ============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lazarus / BeaverTail Bulk SecOps Automation Tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--mode", choices=["scan-only", "pr-ci", "commit-ci"], required=True,
                        help="Operation mode: 'scan-only' audits repos; 'pr-ci' opens integration PRs; 'commit-ci' pushes directly.")
    parser.add_argument("--org", help="Target GitHub organization to process.")
    parser.add_argument("--user", help="Target GitHub user account to process (if different from authenticated user).")
    parser.add_argument("--visibility", choices=["all", "public", "private"], default="all",
                        help="Filter repositories by visibility (default: all).")
    parser.add_argument("--workdir", type=Path, default=DEFAULT_WORK_DIR,
                        help=f"Local working directory for cloning repos (default: {DEFAULT_WORK_DIR}).")
    parser.add_argument("--scanner-path", type=Path, default=Path("./lazarus_scanner.py"),
                        help="Path to lazarus_scanner.py script.")
    parser.add_argument("--workflow-path", type=Path, default=Path("./.github/workflows/lazarus-scan.yml"),
                        help="Path to lazarus-scan.yml workflow file.")
    parser.add_argument("--ssh", action="store_true",
                        help="Use SSH for git cloning instead of HTTPS.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Perform local cloning/committing but skip pushing and creating PRs.")
    parser.add_argument("--protect-branches", action="store_true",
                        help="Enable strict branch protection on the default branch for all processed repositories.")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Number of concurrent workers for processing repositories (default: 5).")
    parser.add_argument("--report-file", type=Path, default=DEFAULT_REPORT_FILE,
                        help=f"Path to save consolidated JSON report (default: {DEFAULT_REPORT_FILE}).")

    return parser.parse_args()

def main() -> int:
    args = parse_args()

    # Validate Paths
    if not args.scanner_path.exists():
        print(f"[!] ERROR: Scanner script not found at '{args.scanner_path}'.", file=sys.stderr)
        return 1
    if not args.workflow_path.exists() and args.mode in ["pr-ci", "commit-ci"]:
        print(f"[!] ERROR: Workflow file not found at '{args.workflow_path}'.", file=sys.stderr)
        return 1

    # Setup Authentication & API
    token = get_github_token()
    api = GitHubAPI(token)

    # Setup Working Directory
    args.workdir.mkdir(parents=True, exist_ok=True)

    print("=====================================================================")
    print("🛡️ Lazarus / BeaverTail Bulk SecOps Automation Tool")
    print(f"[*] Mode        : {args.mode}")
    print(f"[*] Target Org  : {args.org or 'N/A'}")
    print(f"[*] Target User : {args.user or 'Authenticated User'}")
    print(f"[*] Visibility  : {args.visibility}")
    print(f"[*] Work Dir    : {args.workdir.resolve()}")
    print(f"[*] Dry Run     : {args.dry_run}")
    print(f"[*] Protect     : {args.protect_branches}")
    print(f"[*] Concurrency : {args.concurrency}")
    print("=====================================================================")

    # Fetch Repositories
    try:
        repos = api.get_repositories(org=args.org, user=args.user, visibility=args.visibility)
    except Exception as e:
        print(f"[!] ERROR fetching repositories: {e}", file=sys.stderr)
        return 1

    if not repos:
        print("[!] No repositories found matching the criteria.")
        return 0

    print(f"[*] Discovered {len(repos)} repository(ies) for processing.\n")

    # Initialize Git Worker
    worker = GitWorker(
        work_dir=args.workdir,
        scanner_path=args.scanner_path,
        workflow_path=args.workflow_path,
        use_ssh=args.ssh,
        dry_run=args.dry_run,
        protect_branches=args.protect_branches
    )

    # Process Repositories Concurrently
    results: List[RepoResult] = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_to_repo = {executor.submit(worker.process_repo, repo, args.mode, api): repo for repo in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                print(f"[!] Unhandled exception processing {repo.full_name}: {e}", file=sys.stderr)
                results.append(RepoResult(repo=repo, status="FAILED", action_taken="exception", details=str(e)))

    elapsed_time = time.time() - start_time

    # ========================================================================
    # Consolidated Reporting & Summary
    # ========================================================================

    summary = {
        "SUCCESS": 0,
        "FAILED": 0,
        "THREAT_DETECTED": 0,
        "SKIPPED": 0
    }
    for r in results:
        summary[r.status] = summary.get(r.status, 0) + 1

    print("\n=====================================================================")
    print("📊 Bulk SecOps Execution Summary")
    print("=====================================================================")
    print(f"Total Repositories Processed : {len(repos)}")
    print(f"Elapsed Time                 : {elapsed_time:.2f} seconds")
    print(f"✅ Clean / Successfully Exec : {summary['SUCCESS']}")
    print(f"⏭️ Skipped (Already Clean)   : {summary['SKIPPED']}")
    print(f"🚨 Threats Detected          : {summary['THREAT_DETECTED']}")
    print(f"❌ Failed / Errors           : {summary['FAILED']}")
    print("=====================================================================\n")

    # Detailed Table Output
    print(f"{'REPOSITORY':<35} | {'STATUS':<16} | {'ACTION / DETAILS'}")
    print("-" * 80)
    for r in results:
        status_icon = "✅" if r.status == "SUCCESS" else "🚨" if r.status == "THREAT_DETECTED" else "⏭️" if r.status == "SKIPPED" else "❌"
        repo_name = r.repo.full_name[:33]
        if r.pr_url:
            details = f"PR: {r.pr_url}"
        else:
            details = r.details.replace("\n", " ")[:40]
        print(f"{status_icon} {repo_name:<33} | {r.status:<16} | {details}")

    # Generate JSON Report File
    report_data = {
        "execution_meta": {
            "mode": args.mode,
            "target_org": args.org,
            "target_user": args.user,
            "visibility": args.visibility,
            "timestamp": time.time(),
            "elapsed_seconds": elapsed_time,
            "summary": summary
        },
        "repository_results": [
            {
                "repo_name": r.repo.full_name,
                "clone_url": r.repo.clone_url,
                "status": r.status,
                "action_taken": r.action_taken,
                "details": r.details,
                "findings": r.findings,
                "pr_url": r.pr_url
            } for r in results
        ]
    }

    try:
        args.report_file.parent.mkdir(parents=True, exist_ok=True)
        with args.report_file.open("w", encoding="utf-8") as fp:
            json.dump(report_data, fp, indent=2, default=str)
        print(f"\n[*] Detailed JSON report saved to '{args.report_file.resolve()}'.")
    except OSError as e:
        print(f"[!] ERROR saving report file: {e}", file=sys.stderr)

    # Return exit code 1 if threats were detected or failures occurred
    if summary["THREAT_DETECTED"] > 0 or summary["FAILED"] > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
