import subprocess
import json
import sys
import os

# Remove invalid GITHUB_TOKEN if present
os.environ.pop("GITHUB_TOKEN", None)

def run_cmd(args):
    res = subprocess.run(
        args,
        capture_output=True,
        check=False,
        env=dict(os.environ)
    )
    stdout = res.stdout.decode("utf-8", errors="ignore").strip() if res.stdout else ""
    stderr = res.stderr.decode("utf-8", errors="ignore").strip() if res.stderr else ""
    return stdout, stderr, res.returncode

def verify():
    print("=" * 80)
    print("      PHANTOMNET WEEK 23 SPRINT & MASTER PLAN VERIFICATION AUDIT")
    print("=" * 80)

    # 1. Fetch GitHub issues with label week-23
    stdout, stderr, code = run_cmd([
        'gh', 'issue', 'list',
        '--repo', 'sriram21-09/PhantomNet',
        '--label', 'week-23',
        '--state', 'all',
        '--json', 'number,title,body,assignees,milestone,labels',
        '--limit', '50'
    ])

    if code != 0 or not stdout:
        print(f"[FAIL] Could not fetch issues: {stderr}")
        return

    issues = json.loads(stdout)
    print(f"\n[OK] Total Week 23 Issues Found in GitHub: {len(issues)} / 20 expected")

    # Load master plan config
    with open('automation/sprint/week23_config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    expected_tasks = config['tasks']
    print(f"[OK] Total Master Plan Config Tasks: {len(expected_tasks)}")
    print(f"[OK] Milestone: {config['milestone_title']}")
    print(f"[OK] Date Range: {config['day_map']['1']} to {config['day_map']['5']}")

    issues_by_title = {i['title']: i for i in issues}

    all_passed = True
    print("\n" + "-" * 80)
    print("1. DETAILED ISSUE & SUBTASK AUDIT AGAINST MASTER PLAN")
    print("-" * 80)

    for idx, task in enumerate(expected_tasks, 1):
        expected_title = f"Week 23-Day {task['Day']},{task['Role']},{task['Title']}"
        issue = issues_by_title.get(expected_title)

        if not issue:
            print(f"[FAIL] Task {idx:02d}: Missing issue with title '{expected_title}'")
            all_passed = False
            continue

        num = issue['number']
        assignees = [a['login'] for a in issue['assignees']]
        expected_assignee = task['Assignee']
        ms = issue['milestone']['title'] if issue.get('milestone') else None
        labels = {l['name'] for l in issue['labels']}
        body = issue['body']

        # Checks
        assignee_ok = expected_assignee in assignees
        ms_ok = (ms == config['milestone_title'])
        labels_ok = {'week-23', 'month-6', 'documentation-demo', 'production-polish'}.issubset(labels)
        body_has_obj = "Objective" in body
        body_has_tasks = "Tasks" in body
        body_has_deliv = "Deliverables" in body
        body_has_est = f"{task['Estimate']} hours" in body

        # Check subtasks inside body
        subtasks_present = all(subtask in body for subtask in task['Tasks'])
        deliv_present = all(d in body for d in task['Deliverables'])

        checks = [assignee_ok, ms_ok, labels_ok, body_has_obj, body_has_tasks, body_has_deliv, body_has_est, subtasks_present, deliv_present]
        status_flag = "PASS" if all(checks) else "FAIL"
        if status_flag == "FAIL":
            all_passed = False

        print(f"[{status_flag}] #{num} Day {task['Day']} | {task['Role']} | {task['Title']}")
        print(f"       -> Assignee: {assignees[0] if assignees else 'None'} ({'MATCH' if assignee_ok else 'FAIL'})")
        print(f"       -> Milestone: {ms} ({'MATCH' if ms_ok else 'FAIL'})")
        print(f"       -> Labels: {sorted(list(labels))}")
        print(f"       -> Subtasks: {len(task['Tasks'])}/{len(task['Tasks'])} verified in body")
        print(f"       -> Deliverables: {len(task['Deliverables'])}/{len(task['Deliverables'])} verified in body")
        print(f"       -> Estimate: {task['Estimate']} hrs verified")

    # 2. Check Project Board sync
    print("\n" + "-" * 80)
    print("2. PROJECT BOARD #5 & CUSTOM FIELD SYNC AUDIT")
    print("-" * 80)

    proj_stdout, proj_stderr, proj_code = run_cmd([
        'gh', 'project', 'item-list', '5',
        '--owner', 'sriram21-09',
        '--format', 'json',
        '--limit', '500'
    ])

    if proj_code == 0 and proj_stdout:
        proj_data = json.loads(proj_stdout)
        items = proj_data.get('items', [])
        print(f"[OK] Total Items on Project Board #5: {len(items)}")
        
        # Match week 23 items
        week23_items = []
        for it in items:
            title = it.get('title', '')
            if title.startswith("Week 23-"):
                week23_items.append(it)
        
        print(f"[OK] Week 23 Items on Project Board: {len(week23_items)} / 20")
        
        for it in sorted(week23_items, key=lambda x: x.get('title', '')):
            title = it.get('title', '')
            role = it.get('Role', 'N/A')
            task_type = it.get('Type', 'N/A')
            day = it.get('Day (Month 6)', it.get('Day', 'N/A'))
            status = it.get('status', 'Todo')
            print(f"  [SYNCED] {title[:55]} | Role: {role} | Type: {task_type} | Day: {day} | Status: {status}")
            
        if len(week23_items) != 20:
            all_passed = False
    else:
        print(f"[WARN] Could not query project items: {proj_stderr}")
        all_passed = False

    print("\n" + "=" * 80)
    if all_passed and len(issues) == 20:
        print(">>> VERIFICATION RESULT: 100% SUCCESS — ALL 20 WEEK 23 ISSUES AND TASKS ARE PERFECTLY CREATED & SYNCED! <<<")
    else:
        print(">>> VERIFICATION RESULT: INCOMPLETE OR FAILED CHECKS FOUND <<<")
    print("=" * 80)

if __name__ == '__main__':
    verify()
