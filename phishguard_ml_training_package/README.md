# PhishGuard ML Training Package

This package gives you a **real machine-learning training pipeline** for phishing URL detection.

## What it does
- extracts numerical features from URLs
- trains a Random Forest classifier
- exports:
  - `phishguard_model.joblib`
  - `training_metrics.json`

## Train with your real dataset
Prepare a CSV with 2 columns:

- `url`
- `label`  (`1` = phishing, `0` = legitimate)

Example:

```csv
url,label
https://google.com,0
http://secure-paypal-login.xyz/login,1
```

Run:

```bash
python train_phishing_model.py --csv your_dataset.csv --model-out phishguard_model.joblib --metrics-out training_metrics.json
```

## Demo mode
If you do not have a CSV yet:

```bash
python train_phishing_model.py --demo
```

This trains on a generated demo dataset only. It is useful for prototype integration, but **not** for research-grade claims.

## Honest note
A meaningful phishing model needs a real labeled dataset such as:
- PhishTank
- OpenPhish
- Alexa / Tranco / Common Crawl legitimate URLs

