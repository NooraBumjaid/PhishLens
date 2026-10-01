# Scoring validation

This report records the current rule-based behavior of Suspicious URL Analyzer. Scores were not changed for this check. A row is marked PASS only when an automated test confirmed that result.

Command run: `pytest -v`

Result: 72 passed, 0 failed.

Classifications in use:

- 0–30: Low Risk
- 31–60: Suspicious
- 61–100: High Risk

The table in this first section is the Step 10 snapshot, recorded before scoring calibration. Current scores are in [Step 11 — Scoring Calibration](#step-11--scoring-calibration).

## Test matrix

| Test Case | Expected Indicators | Expected Score | Expected Classification | Result |
| --- | --- | --- | --- | --- |
| `https://example.com` | HTTPS −5 | 5/100 | Low Risk | PASS |
| `https://example.com/login` | HTTPS −5, keyword `login` +5 | 10/100 | Low Risk | PASS |
| `http://example.com` | HTTP +10 | 20/100 | Low Risk | PASS |
| `http://192.168.1.10` | HTTP +10, IP hostname +20 | 40/100 | Suspicious | PASS |
| `https://example.com/account/verify/password` | HTTPS −5, keywords +15 | 20/100 | Low Risk | PASS |
| `https://example.com:8080/login` | HTTPS −5, keyword `login` +5, non-standard port +10 | 20/100 | Low Risk | PASS |
| `https://bit.ly/example` | HTTPS −5, URL shortener +15 | 20/100 | Low Risk | PASS |
| `https://xn--example-xxxx.com` | HTTPS −5, Punycode +15 | 20/100 | Low Risk | PASS |
| `https://example.com@evil.example/login` | HTTPS −5, `@` symbol +15, keyword `login` +5 | 25/100 | Low Risk | PASS |
| `https://a.b.c.d.example.com/login` | HTTPS −5, excessive subdomains +10, keyword `login` +5 | 20/100 | Low Risk | PASS |
| Long `https://example.com/` plus padding past 120 characters | HTTPS −5, long URL +10 | 15/100 | Low Risk | PASS |
| `https://g00gle.com/login` | HTTPS −5, keyword `login` +5, possible domain impersonation +15. Evidence includes lookalike substitution and text similarity 67%, not 100%. Wording is "Possible domain impersonation" and says similarity does not prove malicious intent. | 25/100 | Low Risk | PASS |
| `https://google.com` | HTTPS −5. No domain-impersonation indicator. | 5/100 | Low Risk | PASS |
| `https://accounts.google.com` | HTTPS −5. No domain-impersonation indicator. | 5/100 | Low Risk | PASS |
| `https://example.com/google/login` | HTTPS −5, keyword `login` +5. No domain-impersonation indicator. | 10/100 | Low Risk | PASS |
| `http://192.168.1.10:8080/account/verify/password` | HTTP +10, IP hostname +20, keywords +15, non-standard port +10. No domain-impersonation indicator. | 65/100 | High Risk | PASS |
| `https://secure.example.com` | HTTPS −5, keyword `secure` +5 only | 10/100 | Low Risk | PASS |
| `https://accounts.google.com/login` | HTTPS −5, keyword `login` +5. No domain-impersonation indicator. | 10/100 | Low Risk | PASS |
| `https://example.com/paypal/help` | HTTPS −5. No domain-impersonation indicator and no keyword indicator. | 5/100 | Low Risk | PASS |
| `https://example.com:443` | HTTPS −5. No non-standard-port indicator. | 5/100 | Low Risk | PASS |
| `https://example.com/login/login/login` | Keyword `login` counted once at +5, plus HTTPS −5 | 10/100 | Low Risk | PASS |
| `https://example.com/login/verify/account/update/password/secure` | Six unique keywords, contribution capped at +15, plus HTTPS −5 | 20/100 | Low Risk | PASS |
| Synthetic indicators totaling more than 100 | Clamp | 100/100 | High Risk | PASS |
| Synthetic indicators totaling less than 0 | Clamp | 0/100 | Low Risk | PASS |
| Classification boundaries 0, 30, 31, 60, 61, and 100 | Boundary labels | n/a | Low Risk, Low Risk, Suspicious, Suspicious, High Risk, High Risk | PASS |

Every score above starts from the configured base score of 10, then adds the indicator contributions, then clamps the total to 0–100.

## Scoring observations

These results follow the current weights. They were not treated as bugs, and the weights were not changed.

- A typosquatting URL with a login keyword currently remains Low Risk. `https://g00gle.com/login` scores 25/100.
- A shortened URL alone remains Low Risk. `https://bit.ly/example` scores 20/100.
- Multiple credential-related keywords alone may remain Low Risk. `https://example.com/account/verify/password` scores 20/100 even though the keyword contribution is already at its +15 cap.
- One non-standard port plus one login keyword also remains Low Risk at 20/100.
- An `@` symbol plus a login keyword remains Low Risk at 25/100.
- These results may justify future scoring calibration. This step does not choose new weights.

## Current limitations

- The analyzer is rule-based only. It inspects the URL text.
- There is no reputation lookup.
- There is no DNS analysis.
- There is no WHOIS or domain-age analysis.
- There is no live redirect analysis. Shortened URLs are not expanded.
- There is no webpage-content analysis.
- There is no certificate inspection.
- There are no threat-intelligence feeds.
- Domain impersonation uses a small configured reference list: google.com, microsoft.com, apple.com, paypal.com, and amazon.com.
- Similarity detection can produce false positives or false negatives. The displayed percentage is a heuristic, not a probability.
- The risk score is not a probability that a website is malicious.
- HTTPS does not guarantee that a website is trustworthy.

## Heuristic notes from this run

These extra hostnames were checked locally while writing this report. They are observations, not new detection rules.

False-positive risk: names that are one ordinary word away from a reference label are flagged. Confirmed examples are `googles.com`, `apples.com`, `amazons.com`, and `paypalme.com`. Each received the impersonation indicator and scored 20/100, Low Risk.

False-negative risk: names that are similar but below the 0.80 threshold are not flagged. `googlemail.com` scored 5/100 with HTTPS only. The domain split also treats only the last two hostname labels as the domain, so `g00gle.co.uk`, `google.evil.com`, and `accounts.google.com.evil.net` were not flagged. Lookalike letters other than `0`/`o` and `1`/`l` are not folded.

## Step 11 — Scoring Calibration

Calibration changed how existing indicators add up. It did not add detection techniques, and it did not change the typosquatting comparison. Classification boundaries are still 0–30 Low Risk, 31–60 Suspicious, and 61–100 High Risk.

The score is still a heuristic. It is not a probability. High Risk does not prove a URL is malicious, and Low Risk does not guarantee safety. Correlation rules are configured by hand. The domain-impersonation detector still has the false positives and false negatives recorded above. No external reputation source is used.

### Weights changed

| Indicator | Before | After |
| --- | --- | --- |
| `@` symbol | +15 | +20 |
| URL shortener | +15 | +20 |
| Possible domain impersonation | +15 | +20 |

### Weights left unchanged

- Base score: 10
- HTTPS: −5
- HTTP: +10
- IP hostname: +20
- Punycode: +15
- Long URL: +10
- Excessive subdomains: +10
- Non-standard port: +10
- Suspicious keywords: +5 each, capped at +15

### Correlation rules

These are scoring combinations of indicator IDs that the analyzer already reports. Each one is added at most once. They are not new URL checks.

| Rule | Requires | Contribution |
| --- | --- | --- |
| `impersonation_with_credentials` | possible domain impersonation and suspicious keywords | +15 |
| `shortener_with_credentials` | URL shortener and suspicious keywords | +10 |
| `at_symbol_with_credentials` | `@` symbol and suspicious keywords | +10 |
| `ip_with_credentials` | IP hostname and suspicious keywords | +10 |

Correlations were added because a login word, a shortener, or a lookalike name is often ordinary by itself. The same signals are more concerning together. A normal page such as `https://example.com/login` still has no correlation and stays Low Risk.

### Before and after

The After column is confirmed by the automated tests in this step. The Before column is the Step 10 model. For two rows that were not in the Step 10 table, Before is the total those same weights produced before correlations existed.

| URL Pattern | Before | After |
| --- | --- | --- |
| Normal HTTPS login | 10 Low Risk | 10 Low Risk |
| `g00gle.com/login` | 25 Low Risk | 45 Suspicious |
| `g00gle.com` without credential words | 20 Low Risk | 25 Low Risk |
| `bit.ly/example` | 20 Low Risk | 25 Low Risk |
| `bit.ly/account-verify` | 30 Low Risk | 45 Suspicious |
| `@` symbol plus login | 25 Low Risk | 40 Suspicious |
| IP plus `account/verify` | 50 Suspicious | 60 Suspicious |
| Strong IP regression URL | 65 High Risk | 75 High Risk |

`https://g00gle.com` stays Low Risk at 25/100, and the impersonation warning is still shown. The lookalike false positives from Step 10, such as `googles.com`, now use the +20 impersonation weight, so an HTTPS example of that kind scores 25/100 and remains Low Risk.

Confirmed by `pytest -v`: 81 passed, 0 failed.
