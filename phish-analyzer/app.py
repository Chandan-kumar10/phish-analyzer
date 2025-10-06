import streamlit as st
import pandas as pd
import re
import urllib.parse
import random

st.set_page_config(page_title="Simple Phish Analyzer", layout="wide")
st.title("Simple Phish Analyzer — Clean & Helpful")

# -------------------------
# Small UI helpers
# -------------------------
def info_box(txt):
    st.markdown(f"<div style='background:#eef6ff;padding:10px;border-radius:8px;margin-bottom:8px'>{txt}</div>", unsafe_allow_html=True)

def danger_box(txt):
    st.markdown(f"<div style='background:#ffecec;padding:10px;border-radius:8px;margin-bottom:8px'>{txt}</div>", unsafe_allow_html=True)

# -------------------------
# Theme toggle (simple)
# -------------------------
theme = st.sidebar.selectbox("Theme", ["Dark", "Light"], index=1)
if theme == "Dark":
    st.markdown("""
        <style>
        .stApp { background-color: #0b1220; color: #e6eef8; }
        .card { background:#0f1724; padding:12px; border-radius:8px; }
        </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
        <style>
        .stApp { background-color: #f7fbff; color: #041122; }
        .card { background:#ffffff; padding:12px; border-radius:8px; }
        </style>
    """, unsafe_allow_html=True)

# -------------------------
# Simple examples / demo
# -------------------------
SAMPLE_CSV = """recipient,subject,body,links,clicked,reported
alice@example.com,Account Suspended,Your PayPal account has been suspended. Login here: http://paypal-login.com,http://paypal-login.com,False,False
bob@example.com,Team Meeting,Reminder: meeting tomorrow.,,False,True
"""

st.sidebar.markdown("### Actions")
st.sidebar.download_button("Download sample CSV", data=SAMPLE_CSV, file_name="sample_phish_template.csv", mime="text/csv")

# -------------------------
# Upload or simulate
# -------------------------
st.markdown("## 1) Upload CSV or simulate demo data")
col1, col2 = st.columns([2,1])

with col1:
    uploaded = st.file_uploader("Upload CSV (columns: recipient,subject,body,links,clicked,reported)", type=["csv"])
with col2:
    if st.button("Generate demo dataset"):
        # create a reliable demo mix
        data = [
            ["alice@example.com","Account Suspended","Your PayPal account has been suspended. Login here: http://paypal-login.com","http://paypal-login.com","False","False"],
            ["bob@company.com","Team Meeting","Reminder: team meeting tomorrow.","","False","True"],
            ["carol@bank.com","Verify now","Please verify bank details: http://bank-secure.example.com","http://bank-secure.example.com","True","False"],
            ["dave@mail.org","Hello","Monthly newsletter","https://company.com/news","False","False"],
            ["eve@user.com","Password Reset","Reset password: http://192.168.1.100/login","http://192.168.1.100/login","True","False"],
        ]
        df_demo = pd.DataFrame(data, columns=["recipient","subject","body","links","clicked","reported"])
        st.session_state['df'] = df_demo
        st.success("Demo dataset generated — scroll down for analysis.")

# read uploaded CSV if provided
if uploaded:
    try:
        df = pd.read_csv(uploaded, low_memory=False)
        st.session_state['df'] = df
        st.success("Uploaded - ready for analysis.")
    except Exception as e:
        st.error(f"Could not read CSV: {e}")

if 'df' not in st.session_state:
    st.info("No data yet. Upload a CSV or click 'Generate demo dataset'.")
    st.stop()

df = st.session_state['df'].copy()
# ensure required columns exist
for c in ['recipient','subject','body','links','clicked','reported']:
    if c not in df.columns:
        df[c] = ""

# -------------------------
# Heuristics and scoring
# -------------------------
SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly']
URGENCY_KEYWORDS = ['verify','urgent','suspend','suspended','immediately','action required','verify now','login','password','reset','bank','invoice','overdue']

def extract_links(links_field):
    if pd.isna(links_field) or str(links_field).strip() == "":
        return []
    parts = re.split(r'[,\s]+', str(links_field).strip())
    return [p for p in parts if p.startswith('http')]

def domain_of(url):
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except:
        return ""

def is_ip_domain(dom):
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', dom)) or bool(re.match(r'^\d+\.\d+\.\d+\.\d+:\d+', dom))

def score_item(row):
    score = 0
    reasons = []
    text = (str(row.get('subject','')) + " " + str(row.get('body',''))).lower()

    # urgency words
    for kw in URGENCY_KEYWORDS:
        if kw in text:
            score += 12
            if kw not in reasons:
                reasons.append(f"Contains urgent word: '{kw}'")

    # links analysis
    links = extract_links(row.get('links',''))
    if links:
        score += 10  # presence of link raises risk
        for link in links:
            dom = domain_of(link)
            if dom == "":
                continue
            # missing https
            if not link.lower().startswith('https://'):
                score += 8
                reasons.append(f"Link not using HTTPS: {link}")
            # IP based
            if is_ip_domain(dom):
                score += 25
                reasons.append(f"IP-based link: {dom}")
            # shortener
            if any(s in dom for s in SHORTENERS):
                score += 18
                reasons.append(f"URL shortener used: {dom}")
            # suspicious chars or many subdomains (lookalike)
            if '-' in dom or dom.count('.') > 2:
                score += 8
                reasons.append(f"Suspicious domain pattern: {dom}")
            # brand mismatch: check for brand words in text but not in domain
            for brand in ['paypal','google','apple','amazon','bank']:
                if brand in text and brand not in dom:
                    score += 18
                    reasons.append(f"Brand mention but link domain mismatch: {brand} vs {dom}")
    else:
        # no links reduces some risk for credential phishing but not content-based
        pass

    # clicked / reported behavior
    clicked = str(row.get('clicked','')).strip().lower() in ['true','1','yes']
    reported = str(row.get('reported','')).strip().lower() in ['true','1','yes']
    if clicked:
        score += 22
        reasons.append("User clicked the link")
    if reported:
        score -= 28
        reasons.append("User reported the email (reduces risk)")

    # clamp and label
    score = max(0, min(100, score))
    label = 'Low' if score < 30 else ('Medium' if score < 60 else 'High')
    return score, label, list(dict.fromkeys(reasons))  # preserve order, dedupe

# apply scoring
scored = df.apply(lambda r: score_item(r), axis=1)
df['risk_score'] = [s[0] for s in scored]
df['risk_label'] = [s[1] for s in scored]
df['reasons'] = [s[2] for s in scored]

# -------------------------
# Dashboard: overview
# -------------------------
st.markdown("## 2) Overview")
colA, colB, colC = st.columns(3)
colA.metric("Total Emails", len(df))
colB.metric("High Risk", int((df['risk_label']=='High').sum()))
colC.metric("Reported", int(df['reported'].astype(str).str.lower().isin(['true','1','yes']).sum()))

st.markdown("### Risk Distribution")
dist = df['risk_label'].value_counts().reindex(['High','Medium','Low']).fillna(0)
st.bar_chart(dist)

# -------------------------
# Email list (simple & clear)
# -------------------------
st.markdown("### 3) Emails (click a row to inspect)")
# show compact table
display = df[['recipient','subject','risk_score','risk_label']].sort_values('risk_score', ascending=False).reset_index(drop=True)
# color-coded labels - simple html rendering
rows_html = ""
for i, r in display.iterrows():
    color = "#3fc57a" if r['risk_label']=='Low' else ("#ffb400" if r['risk_label']=='Medium' else "#ff4d4f")
    rows_html += f"""
    <div style="padding:10px;border-radius:8px;margin-bottom:6px;background:rgba(255,255,255,0.03)">
      <b>{r['recipient']}</b> — {r['subject']} <span style='float:right;background:{color};padding:4px 8px;border-radius:6px;color:#fff'>{r['risk_label']} ({int(r['risk_score'])})</span>
    </div>
    """
st.markdown(rows_html, unsafe_allow_html=True)

# -------------------------
# Inspect single recipient & give advice
# -------------------------
st.markdown("### 4) Inspect & Advice")
recipients = df['recipient'].tolist()
sel = st.selectbox("Pick recipient to inspect", options=recipients)
row = df[df['recipient']==sel].iloc[0]

st.markdown(f"**Subject:** {row['subject']}")
st.markdown(f"**Body (preview):** {row['body'][:400]}{'...' if len(str(row['body']))>400 else ''}")
links = extract_links(row['links'])
if links:
    st.markdown("**Links found:**")
    for L in links:
        st.write("-", L)
else:
    st.write("**Links found:** None")

st.markdown(f"**Risk score:** **{int(row['risk_score'])}** — **{row['risk_label']}**")

st.markdown("**Why flagged (reasons):**")
if row['reasons']:
    for r in row['reasons']:
        st.write("- " + r)
else:
    st.write("- No automated reason flagged")

# Simple actionable advice (non-technical)
st.markdown("**Actionable advice:**")
advice = []
if row['risk_label'] == 'High':
    advice.append("• Do NOT click links or enter credentials on linked pages.")
    advice.append("• Change password on the real site (manually visit official site).")
    advice.append("• Enable 2FA if available.")
    advice.append("• Report this email to your IT/security team.")
elif row['risk_label'] == 'Medium':
    advice.append("• Be cautious. Hover over links to see actual URL before clicking.")
    advice.append("• Verify sender's email address and spelling.")
    advice.append("• If unsure, ask your IT team or the sender via a separate channel.")
else:
    advice.append("• Looks low-risk but stay alert for unexpected requests.")
    advice.append("• Do not share passwords / OTPs via email.")

for a in advice:
    st.write(a)

# -------------------------
# Paste your email content quick-check
# -------------------------
st.markdown("### 5) Quick-check: Paste email content (subject + body + links)")
st.caption("Paste only non-sensitive text (do NOT paste passwords/OTP). Example: 'Subject: ... Body: ... http://...'")
text = st.text_area("Paste email content here", height=130)
if st.button("Quick Analyze pasted text"):
    # make a synthetic row and score
    fake = {'subject': text[:120], 'body': text, 'links': text, 'clicked': False, 'reported': False}
    s, lab, reasons = score_item(fake)
    if s >= 60:
        danger_box(f"🚨 HIGH RISK — score {int(s)} ({lab})")
    elif s >= 30:
        info_box(f"⚠️ MEDIUM RISK — score {int(s)} ({lab})")
    else:
        info_box(f"✅ LOW RISK — score {int(s)} ({lab})")
    if reasons:
        st.write("Reasons detected:")
        for r in reasons:
            st.write("- " + r)
    else:
        st.write("- No obvious reasons detected. Stay cautious.")

# -------------------------
# Export analyzed CSV
# -------------------------
st.markdown("### 6) Export analyzed CSV")
csv_out = df.to_csv(index=False).encode('utf-8')
st.download_button("Download analyzed CSV", data=csv_out, file_name="phish_analyzed.csv", mime="text/csv")

st.markdown("---")
st.caption("Made simple for non-technical users — scoring is heuristic-based and conservative. For production use integrate threat-intel APIs or ML models.")
