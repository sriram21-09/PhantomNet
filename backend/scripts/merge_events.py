import pandas as pd

BENIGN_PATH = "data/week6_base_events.csv"
ATTACK_PATH = "data/week6_test_events.csv"
OUTPUT_PATH = "data/week6_mixed_events.csv"

print("[*] Loading benign events (robust mode)...")

benign = pd.read_csv(
    BENIGN_PATH,
    engine="python",          # handles malformed CSVs
    on_bad_lines="skip"       # skip broken rows safely
)

print(f"[+] Loaded benign rows: {len(benign)}")

print("[*] Loading attack events...")
attacks = pd.read_csv(ATTACK_PATH)
print(f"[+] Loaded attack rows: {len(attacks)}")

# Ensure benign semantics
if "attack_type" not in benign.columns:
    benign["attack_type"] = "BENIGN"
else:
    benign["attack_type"] = "BENIGN"

benign["is_malicious"] = False
benign["threat_score"] = 0.0

# Align columns (union of both)
all_columns = set(benign.columns).union(set(attacks.columns))

benign = benign.reindex(columns=all_columns, fill_value=None)
attacks = attacks.reindex(columns=all_columns, fill_value=None)

merged = pd.concat([benign, attacks], ignore_index=True)

merged.to_csv(OUTPUT_PATH, index=False)

print("\n[✓] Merged dataset created")
print("Rows:", len(merged))
print("\nAttack type distribution:")
print(merged["attack_type"].value_counts())
print("\nMalicious flag distribution:")
print(merged["is_malicious"].value_counts())
