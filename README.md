# Phish-Analyzer

Phish-Analyzer is a defensive tool that ingests phishing campaign logs (e.g., exported from GoPhish),
normalizes them, computes explainable per-user risk scores, and provides a Streamlit dashboard for visualization and export.

## Features
- Normalize GoPhish CSV (prepare_csv.py)
- Rule-based risk scoring (keywords, suspicious links, clicked/reported behaviour)
- Streamlit UI: upload CSV, view table, charts, top risky users, export report
- Simulator for demo mode (generate fake logs)

## Quickstart (local)
```bash
# create & activate venv (Windows PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# install deps
pip install -r requirements.txt

# prepare CSV (if needed)
python prepare_csv.py "path/to/gophish_results.csv" prepared_for_analyzer.csv

# run app
python -m streamlit run app.py
