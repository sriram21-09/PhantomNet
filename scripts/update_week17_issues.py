import json
import subprocess
import sys
import os

# Set python path to find create_week17_issues.py in the same folder
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from create_week17_issues import tasks_definition, REPO

# Configure stdout and stderr to support UTF-8/emojis on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

def run_gh_cmd(args):
    """Run a gh CLI command and return the parsed JSON response or output string."""
    cmd = ["gh"] + args
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if res.returncode != 0:
        print(f"Error running command: {' '.join(cmd)}")
        return None
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return res.stdout.strip()

def main():
    print("Fetching active GitHub issues...")
    issues = run_gh_cmd([
        "issue", "list",
        "--repo", REPO,
        "--label", "week-17",
        "--limit", "100",
        "--json", "number,title,body"
    ])
    
    if not issues:
        print("No issues found or failed to fetch.")
        return
        
    print(f"Found {len(issues)} Week 17 issues. Updating modified ones...")
    
    for t in tasks_definition:
        expected_title = f"Week 17-Day {t['day']},{t['role']},{t['title']}"
        
        # Find matching issue on Github
        matching_issue = None
        for iss in issues:
            if iss["title"].strip() == expected_title.strip():
                matching_issue = iss
                break
                
        if not matching_issue:
            print(f"⚠️ Could not find GitHub issue matching title: '{expected_title}'")
            continue
            
        issue_number = matching_issue["number"]
        
        # Re-build body
        body = f"""## 🎯 Objective
{t['objective']}

## 🛠️ Tasks
{chr(10).join(t['tasks'])}

## 📦 Deliverables
{chr(10).join(t['deliverables'])}

## ⏱️ Estimate
{t['estimate']} hours

---
#PhantomNet #Week17 #{t['role_tag']}
"""
        # Update the issue body via gh CLI
        print(f"Updating Issue #{issue_number}: {expected_title}...")
        res = subprocess.run([
            "gh", "issue", "edit", str(issue_number),
            "--repo", REPO,
            "--body", body
        ], capture_output=True, text=True, encoding="utf-8")
        
        if res.returncode == 0:
            print(f"  ✅ Issue #{issue_number} updated.")
        else:
            print(f"  ❌ Failed to update Issue #{issue_number}: {res.stderr}")

if __name__ == "__main__":
    main()
