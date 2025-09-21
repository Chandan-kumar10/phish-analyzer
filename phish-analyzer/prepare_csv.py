# prepare_csv.py
import sys
import pandas as pd

if len(sys.argv) < 3:
    print("Usage: python prepare_csv.py input.csv output.csv")
    sys.exit(1)

inp = sys.argv[1]
out = sys.argv[2]

df = pd.read_csv(inp, low_memory=False)

# 1) Ensure recipient exists (map from common names)
if 'recipient' not in df.columns:
    if 'email' in df.columns:
        df = df.rename(columns={'email':'recipient'})
    elif 'recipient_email' in df.columns:
        df = df.rename(columns={'recipient_email':'recipient'})
    else:
        # try to find any column that looks like an email column
        email_cols = [c for c in df.columns if 'email' in c.lower()]
        if email_cols:
            df = df.rename(columns={email_cols[0]:'recipient'})

# 2) Ensure clicked column (True/False)
if 'clicked' not in df.columns:
    # prefer clicked_at or any click-like column
    click_candidates = [c for c in df.columns if 'click' in c.lower()]
    if click_candidates:
        col = click_candidates[0]
        # if values look like timestamps or non-empty -> True
        df['clicked'] = df[col].apply(lambda x: 'True' if str(x).strip() not in ('', 'nan', 'NaN', 'None') else 'False')
    else:
        # fallback: if status column exists and contains 'clicked' text
        status_cols = [c for c in df.columns if 'status' in c.lower()]
        if status_cols:
            s = status_cols[0]
            df['clicked'] = df[s].apply(lambda x: 'True' if (isinstance(x, str) and 'click' in x.lower()) else 'False')
        else:
            # no info -> default False
            df['clicked'] = 'False'

# 3) Ensure reported column
if 'reported' not in df.columns:
    report_candidates = [c for c in df.columns if 'report' in c.lower()]
    if report_candidates:
        df['reported'] = df[report_candidates[0]].apply(lambda x: 'True' if str(x).strip().lower() not in ('', 'nan', 'none', 'false') else 'False')
    else:
        df['reported'] = 'False'

# 4) Ensure subject, body, links columns exist (create empty if missing)
for col in ['subject', 'body', 'links']:
    if col not in df.columns:
        df[col] = ""

# 5) Final check: ensure 'recipient' exists
if 'recipient' not in df.columns:
    # create a placeholder so analyzer won't crash (won't be useful though)
    df['recipient'] = df.index.astype(str) + "@example.local"

# 6) Save prepared CSV
df.to_csv(out, index=False)
print("Prepared CSV saved to:", out)
