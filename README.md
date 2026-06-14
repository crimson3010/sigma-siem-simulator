# Classroom SIEM Simulator

A Python/Streamlit SIEM simulation for cybersecurity classes. Students configure an organization, generate assets, receive continuous synthetic logs, triage alerts, assign tickets to analysts, and hunt for hidden attacks that the SIEM does not automatically recognize.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m streamlit run app.py
```

Mac/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m streamlit run app.py
```

## New Features

- Analyst configuration
- Automatic and manual ticket assignment
- Triage status, classification, disposition, and investigation notes
- Hidden easter egg attacks that only appear as correlated low/noise logs
- Threat taxonomy view
- Cross-device and cross-tool correlation using correlation IDs
- Manual reveal button to convert discovered hidden activity into a Critical alert

## Teaching Use

1. Load demo data or create an organization.
2. Add analysts or student groups.
3. Run the live simulation.
4. Students triage standard alerts.
5. Students hunt for hidden easter eggs using the Live Logs, Threat Taxonomy, and Hidden Easter Eggs tabs.
6. Students document their analysis in notes and export CSVs for reporting.
