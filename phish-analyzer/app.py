# app.py
import streamlit as st
import pandas as pd
import re, urllib.parse, random, string
from io import StringIO
import matplotlib.pyplot as plt

st.set_page_config(page_title="Phish Analyzer (Self)", layout="wide")
st.title("Phish Analyzer — Simulator + CSV Analyzer (Defensive)")

# ---------------- Sample CSV template ----------------
SAMPLE_CSV = """recipient,subject,body,links,clicked,reported
alice@example.com,Account Suspended,Your PayPal account has been suspended. Login here: http://paypal-login.com,http://paypal-login.com,False,False
bob@example.com,Urgent: Verify Now,Please verify your bank details: http://bank-secure.example.com,http://bank-secure.example.com,True,False
charlie@example.com,Team Meeting,Reminder: team meeting tomorrow.,,False,True
"""

# ---------------- Small simulator (optional) ----------------
def random_email(name=None):
    names = ["alice","bob","charlie","dave","eve","frank","grace","harry","irene","jack","kumar","prince"]
    nm = name or random.choice(names)
    doms = ["example.com","company.com","student.edu","mail.org"]
    return f"{nm}{random.randint(1,99)}@{random.choice(doms)}"

suspicious_domains = [
    "paypal-login.com","bank-secure.example.com","secure-paypal.co","invoices-paypal.net",
    "free-gift-login.xyz"
]
benign_domains = ["company.com","example.com","student.edu","trusted.org"]

def gen_link(suspicious=True):
    if suspicious:
        return "http://" + random.choice(suspicious_domains) + "/" + ''.join(random.choices(string.ascii_lowercase, k=6))
    else:
        return "https://"+random.choice(benign_domains)+"/"+''.join(random.choices(string.ascii_lowercase,k=6))

phish_subjects = [
    "Account Suspended - Verify Now",
    "Urgent: Verify Your Bank Details",
    "Security Alert - New Sign-in",
    "Invoice Overdue - Pay Immediately",
    "Team Meeting Reminder",
    "Password Reset Required"
]
phish_bodies = [
    "Dear user, your account has been suspended. Login here: {link}",
    "Please verify your bank details to avoid suspension: {link}",
    "We detected a new sign-in. If this wasn't you click: {link}",
    "You have an overdue invoice. Pay now: {link}",
    "Reminder: team meeting tomorrow at 11 AM.",
    "Reset your password immediately by visiting: {link}" 
]

def simulate_campaign(num_recipients=20, phishing_fraction=0.6, click_rate=0.25, report_rate=0.05):
    rows = []
    names = ["alice","bob","charlie","dave","eve","frank","grace","harry","irene","jack","kumar","prince","ritik","aman","rahul"]
    for i in range(num_recipients):
        r = random_email(random.choice(names))
        is_phish = random.random() < phishing_fraction
        if is_phish:
            subj = random.choice(phish_subjects)
            body_template = random.choice(phish_bodies)
            link = gen_link(suspicious=random.random() < 0.9)
            body = body_template.format(link=link)
            links_field = link
        else:
            subj = random.choice(["Team Meeting","Hello from HR","Monthly Newsletter","Event Reminder"])
            body = "This is a normal internal communication."
            links_field = "" if random.random()<0.8 else gen_link(suspicious=False)
        clicked = random.random() < (click_rate if is_phish else 0.01)
        reported = random.random() < (report_rate if is_phish else 0.005)
        rows.append({
            "recipient": r,
            "subject": subj,
            "body": body,
            "links": links_field,
            "clicked": "True" if clicked else "False",
            "reported": "True" if reported else "False"
        })
    df = pd.DataFrame(rows)
    return df

# ---- Heuristics & helpers ----
keywords = ['suspend','suspended','verify','urgent','account suspended','bank details','password','invoice overdue','security alert','click here','login','reset']

def extract_links(links_field):
    if pd.isna(links_field) or str(links_field).strip()=="":
        return []
    parts = re.split(r'[,\s]+', str(links_field).strip())
    return [p for p in parts if p.startswith('http')]

def domain_of(url):
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except:
        return ""

def score_row(row):
    score = 0
    body = (str(row.get('body','')) + " " + str(row.get('subject',''))).lower()
    for kw in keywords:
        if kw in body:
            score += 15
    links = extract_links(row.get('links',''))
    if links:
        score += 20
        for link in links:
            dom = domain_of(link)
            if '-' in dom or 'login' in dom or 'secure' in dom or dom.count('.')>2:
                score += 10
            if 'paypal' in body and 'paypal.com' not in dom:
                score += 20
    if str(row.get('clicked','')).strip().lower() in ['true','1','yes']:
        score += 25
    if str(row.get('reported','')).strip().lower() in ['true','1','yes']:
        score -= 30
    score = max(0, min(100, score))
    return score

def risk_label(s):
    if s >= 60: return 'High'
    if s >= 30: return 'Medium'
    return 'Low'

# ---------------- UI: template, simulator, upload ----------------
st.sidebar.header("Actions & Settings")
num = st.sidebar.number_input("Simulate: recipients", value=20, min_value=5, max_value=500, step=5)
phish_frac = st.sidebar.slider("Simulate: phish fraction", 0.0, 1.0, 0.6)
click_rate = st.sidebar.slider("Simulate: click probability (for phish)", 0.0, 1.0, 0.25)
report_rate = st.sidebar.slider("Simulate: report probability (for phish)", 0.0, 1.0, 0.05)

st.markdown("### 1) Download sample CSV (template)")
st.download_button("Download sample CSV template", data=SAMPLE_CSV, file_name="sample_phish_template.csv", mime="text/csv")

st.markdown("### 2) Either simulate a campaign (generate logs) or upload GoPhish CSV")
col1, col2 = st.columns(2)
with col1:
    if st.button("Simulate campaign (generate logs)"):
        st.session_state['sim_df'] = simulate_campaign(num_recipients=int(num), phishing_fraction=float(phish_frac), click_rate=float(click_rate), report_rate=float(report_rate))
        st.success("Simulation created — scroll down to see analysis.")
with col2:
    uploaded = st.file_uploader("Or upload CSV (exported from GoPhish)", type=['csv'])
    if uploaded is not None:
        # read uploaded csv
        try:
            df_up = pd.read_csv(uploaded)
        except Exception as e:
            st.error(f"Could not read CSV: {e}")
            st.stop()
        # mapping if columns missing
        required_cols = ['recipient','subject','body','links','clicked','reported']
        uploaded_cols = list(df_up.columns)
        missing = [c for c in required_cols if c not in uploaded_cols]
        if not missing:
            st.session_state['sim_df'] = df_up
            st.success("Uploaded CSV has required columns. Proceeding.")
        else:
            st.warning(f"Missing columns: {missing}")
            st.info("Map your CSV columns to required fields below.")
            mapping = {}
            for req in required_cols:
                mapping[req] = st.selectbox(f"Map required '{req}' to uploaded column:", options=["-- none --"] + uploaded_cols, index=0, key=f"map_{req}")
            unmapped = [k for k,v in mapping.items() if v == "-- none --"]
            if unmapped:
                st.error(f"Please map these fields to proceed: {unmapped}")
                st.stop()
            rename_map = {mapping[k]: k for k in mapping}
            df_up = df_up.rename(columns=rename_map)
            st.session_state['sim_df'] = df_up
            st.success("Mapping applied. Proceeding with analysis.")

if 'sim_df' not in st.session_state:
    st.info("No logs yet — either simulate or upload a CSV. Use the sample template if unsure.")
    st.stop()

# ---------------- Analysis ----------------
df = st.session_state['sim_df']
for c in ['recipient','subject','body','links','clicked','reported']:
    if c not in df.columns:
        df[c] = ""

df['links_list'] = df['links'].apply(extract_links)
df['risk_score'] = df.apply(score_row, axis=1)
df['risk_label'] = df['risk_score'].apply(risk_label)

st.markdown("## Analysis results")
st.write("Total emails:", len(df))
st.dataframe(df[['recipient','subject','links_list','clicked','reported','risk_score','risk_label']].sort_values('risk_score', ascending=False))

# metrics and charts
colA, colB, colC = st.columns(3)
with colA:
    st.metric("Total Emails", len(df))
with colB:
    st.metric("High Risk", int((df['risk_label']=='High').sum()))
with colC:
    st.metric("Reported", int((df['reported'].astype(str).str.lower().isin(['true','1','yes'])).sum()))

st.markdown("### Risk Distribution")
counts = df['risk_label'].value_counts()
fig1, ax1 = plt.subplots(figsize=(4,4))
ax1.pie(counts, labels=counts.index, autopct='%1.1f%%')
ax1.set_title("Risk Distribution")
st.pyplot(fig1)

st.markdown("### Top risky recipients (explainable)")
top = df.sort_values('risk_score', ascending=False).head(8)
st.table(top[['recipient','risk_score','risk_label','links_list','clicked','reported']])

# download analyzed CSV
csv_out = df.to_csv(index=False).encode('utf-8')
st.download_button("Export analyzed CSV", data=csv_out, file_name="phish_analyzed.csv", mime="text/csv")

# explain top row
st.markdown("### Why top user is risky (example explanation)")
top_row = df.sort_values('risk_score', ascending=False).head(1)
if not top_row.empty:
    row = top_row.iloc[0].to_dict()
    st.write("Recipient:", row.get('recipient'))
    st.write("Risk score:", row.get('risk_score'))
    st.write("Rules fired:")
    reasons = []
    b = (str(row.get('subject','')) + " " + str(row.get('body',''))).lower()
    for kw in keywords:
        if kw in b:
            reasons.append(f"Found keyword: '{kw}'")
    for link in extract_links(row.get('links','')):
        dom = domain_of(link)
        if '-' in dom or 'login' in dom or 'secure' in dom:
            reasons.append(f"Suspicious domain pattern: {dom}")
        if 'paypal' in b and 'paypal.com' not in dom:
            reasons.append("Brand mismatch (mentions paypal but link not paypal.com)")
    if str(row.get('clicked','')).strip().lower() in ['true','1','yes']:
        reasons.append("User clicked the link (increases risk)")
    if str(row.get('reported','')).strip().lower() in ['true','1','yes']:
        reasons.append("User reported this email (reduces risk)")
    if reasons:
        for r in reasons:
            st.write("- " + r)
    else:
        st.write("- No rule matched; likely Low risk.")
