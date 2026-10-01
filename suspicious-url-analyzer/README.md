# Suspicious URL Analyzer

A local Flask application that scores a URL from its text. It does not open the submitted website.

## Run

From this folder, with the virtual environment active:

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

Run the tests with:

```powershell
pytest
```

## Optional Reputation Configuration

Reputation checking is optional. The local score works without it.

1. Copy `.env.example` to `.env`.
2. Never commit `.env`. It is listed in `.gitignore`. Commit `.env.example` only.
3. A future VirusTotal API key belongs in `.env` as `VIRUSTOTAL_API_KEY`. Do not paste that key into Python files, templates, or `.env.example`.
4. `ENABLE_REPUTATION_CHECKS` turns the optional check on or off. Enabled values are `true`, `True`, `1`, and `yes`.
5. This step does not send URLs to VirusTotal. When the setting is on and a key is present, the results page only says the integration is ready for a later live check.

## SQLite Scan Storage

SQLite stores local scan history in `database/scans.db`. Python creates that file the first time an analysis is saved. Restarting the app does not delete earlier scans.

Each completed analysis is stored as three kinds of rows:

- A scan row stores the hostname, normalized URL, final score, classification, recommendation, and UTC timestamp.
- Indicator rows store each detected security indicator for that scan.
- Correlation rows store combination bonuses separately from indicators.

Runtime `.db` files are listed in `.gitignore`, so scan history is not committed. API keys are not stored in SQLite. A later dashboard can read this database.

Submitting the form once saves one scan, and the results page shows `Scan ID: #...`. Refreshing that results page can submit the form again, which saves another scan. There is no history page yet.
