import os
import re

def check_md_images(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # find all markdown images ![alt](path)
    pattern = r'!\[.*?\]\((.*?)\)'
    matches = re.findall(pattern, content)
    dir_path = os.path.dirname(filepath)
    
    missing = []
    for match in matches:
        # ignore external web links
        if match.startswith('http://') or match.startswith('https://'):
            continue
        # resolve relative path
        target = os.path.normpath(os.path.join(dir_path, match))
        if not os.path.exists(target):
            missing.append((match, target))
    return missing

files_to_check = [
    'README.md',
    'docs/presentations/week23_presentation_outline.md',
    'docs/reports/final_report_section4_frontend.md',
    'docs/reports/final_report_section3_ml_llm.md',
    'docs/reports/final_report_section2_security.md',
    'docs/week23_frontend_signoff.md',
    'docs/week23_ai_ml_signoff.md',
    'docs/ml_dashboard_design.md',
    'docs/diagrams/pipeline_architecture.md'
]

print('=== Markdown Image Link Verification ===')
all_ok = True
for md in files_to_check:
    missing = check_md_images(md)
    if missing is None:
        continue
    if missing:
        all_ok = False
        print(f'[FAIL] {md}: Broken links found:')
        for raw, norm in missing:
            print(f'   - Link: "{raw}" -> Resolved: "{norm}"')
    else:
        print(f'[OK] {md}: All image links valid!')

if all_ok:
    print('\nAll markdown image links verified successfully!')
