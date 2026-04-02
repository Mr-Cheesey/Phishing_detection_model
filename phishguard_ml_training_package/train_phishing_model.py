
import re
import math
import random
import argparse
from urllib.parse import urlparse, parse_qs
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split


TRUSTED_DOMAINS = [
    "google.com","github.com","microsoft.com","apple.com","amazon.com",
    "paypal.com","wikipedia.org","mozilla.org","openai.com","reddit.com",
    "linkedin.com","netflix.com","dropbox.com","spotify.com","adobe.com",
    "chase.com","wellsfargo.com","bankofamerica.com","facebook.com","instagram.com"
]

SUSPICIOUS_KEYWORDS = [
    "login","verify","secure","update","bank","account","signin","wallet",
    "payment","confirm","password","billing","recover","reset","unlock",
    "validate","suspend","credential","authenticate","reactivate","urgent",
    "alert","notice","invoice","refund","claim","prize","winner","free",
    "offer","limited","expire","activity","suspicious","breach",
]

RISKY_TLDS = {
    "xyz","top","info","click","buzz","shop","live","loan","review","win",
    "date","icu","monster","vip","pw","cf","tk","ml","ga"
}

SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","rb.gy","is.gd","v.gd","tiny.cc"
}

BRANDS = ["paypal","google","amazon","microsoft","apple","facebook","instagram","netflix","linkedin","github"]

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j-1] + 1
            dele = prev[j] + 1
            sub = prev[j-1] + (ca != cb)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]

def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        return "https://" + url
    return url

def is_ip(host: str) -> int:
    return int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host or "")))

def base_domain(host: str) -> str:
    host = re.sub(r"^www\.", "", host.lower())
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def extract_features(url: str) -> dict:
    url = normalize_url(url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    bd = base_domain(host)
    first_label = host.split(".")[0] if host else ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()
    tld = host.split(".")[-1] if "." in host else host

    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full)
    special_char_count = len(re.findall(r"[@_\-=%]", full))
    dot_count = host.count(".")
    subdomain_count = max(0, dot_count - 1)
    redirect_param_count = sum(1 for p in ["redirect","url","goto","next","return","forward","dest"] if p in query.lower())
    encoded_count = len(re.findall(r"%[0-9a-f]{2}", full, re.I))
    has_at = int("@" in full)
    https_enabled = int(parsed.scheme == "https")
    hostname_entropy = shannon_entropy(re.sub(r"\.", "", bd))
    path_depth = path.count("/")
    length = len(full)
    path_length = len(path)
    digit_ratio = (sum(ch.isdigit() for ch in full) / max(1, len(full)))
    hyphen_count = host.count("-")
    risky_tld = int(tld in RISKY_TLDS)
    shortener = int(host in SHORTENERS)
    brand_similarity = 1.0
    brand_exact_mismatch = 0
    for brand in BRANDS:
        dist = levenshtein(first_label[:max(len(brand),1)], brand)
        brand_similarity = min(brand_similarity, dist / max(len(brand), 1))
        if brand in host and bd != f"{brand}.com":
            brand_exact_mismatch = 1

    trusted_base = int(bd in TRUSTED_DOMAINS)
    first_label_len = len(first_label)
    query_param_count = len(parse_qs(query))
    non_ascii = int(any(ord(c) > 127 for c in host))
    punycode = int("xn--" in host)

    return {
        "url_length": length,
        "path_length": path_length,
        "special_char_count": special_char_count,
        "dot_count": dot_count,
        "subdomain_count": subdomain_count,
        "keyword_hits": keyword_hits,
        "has_ip": is_ip(host),
        "https_enabled": https_enabled,
        "hostname_entropy": hostname_entropy,
        "redirect_param_count": redirect_param_count,
        "encoded_count": encoded_count,
        "has_at": has_at,
        "path_depth": path_depth,
        "digit_ratio": digit_ratio,
        "hyphen_count": hyphen_count,
        "risky_tld": risky_tld,
        "shortener": shortener,
        "brand_similarity": brand_similarity,
        "brand_exact_mismatch": brand_exact_mismatch,
        "trusted_base": trusted_base,
        "first_label_len": first_label_len,
        "query_param_count": query_param_count,
        "non_ascii": non_ascii,
        "punycode": punycode,
    }

def build_dataframe(urls):
    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(rows)

def make_demo_dataset(n_per_class: int = 1000, seed: int = 42):
    random.seed(seed)
    safe_urls = []
    phish_urls = []

    safe_paths = ["/", "/login", "/account", "/pricing", "/docs", "/about", "/security"]
    phish_tlds = ["xyz","top","info","click","live","shop"]
    lure_words = ["secure","verify","update","login","account","billing","confirm","signin"]

    for _ in range(n_per_class):
        dom = random.choice(TRUSTED_DOMAINS)
        scheme = random.choice(["https","https","https","http"])
        path = random.choice(safe_paths)
        safe_urls.append(f"{scheme}://{dom}{path}")

    for _ in range(n_per_class):
        brand = random.choice(BRANDS)
        typo = brand[:-1] + random.choice("01l1") if len(brand) > 3 else brand + "1"
        host = random.choice([
            f"{brand}-{random.choice(lure_words)}-{random.choice(lure_words)}.{random.choice(phish_tlds)}",
            f"{typo}-secure-{random.choice(lure_words)}.{random.choice(phish_tlds)}",
            f"{random.choice(lure_words)}-{brand}-account.{random.choice(phish_tlds)}",
            f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        ])
        q = random.choice([
            "",
            "?redirect=http://evil.com",
            "?next=login&token=abc123",
            "?returnUrl=%2Faccount%2Fverify",
        ])
        path = random.choice(["/login","/verify","/update","/signin","/account/verify"])
        scheme = random.choice(["http","http","https"])
        phish_urls.append(f"{scheme}://{host}{path}{q}")

    df = pd.DataFrame({
        "url": safe_urls + phish_urls,
        "label": [0] * len(safe_urls) + [1] * len(phish_urls),
    })
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

def train_model(df: pd.DataFrame, model_out: Path, metrics_out: Path):
    X = build_dataframe(df["url"].tolist())
    y = df["label"].astype(int).to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    imputer = SimpleImputer(strategy="median")
    X_train_imp = imputer.fit_transform(X_train)
    X_test_imp = imputer.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=14,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train_imp, y_train)

    proba = clf.predict_proba(X_test_imp)[:, 1]
    preds = (proba >= 0.5).astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y_test, preds)),
        "precision": float(precision_score(y_test, preds)),
        "recall": float(recall_score(y_test, preds)),
        "f1": float(f1_score(y_test, preds)),
        "auc_roc": float(roc_auc_score(y_test, proba)),
        "confusion_matrix": confusion_matrix(y_test, preds).tolist(),
        "report": classification_report(y_test, preds),
        "features": X.columns.tolist(),
        "feature_importance": dict(sorted(
            zip(X.columns.tolist(), clf.feature_importances_.tolist()),
            key=lambda kv: kv[1], reverse=True
        )),
    }

    payload = {
        "model": clf,
        "imputer": imputer,
        "features": X.columns.tolist(),
    }
    joblib.dump(payload, model_out)
    metrics_out.write_text(pd.Series(metrics).to_json(indent=2))
    return metrics

def main():
    ap = argparse.ArgumentParser(description="Train phishing URL model.")
    ap.add_argument("--csv", type=str, help="CSV with columns: url,label")
    ap.add_argument("--model-out", type=str, default="phishguard_model.joblib")
    ap.add_argument("--metrics-out", type=str, default="training_metrics.json")
    ap.add_argument("--demo", action="store_true", help="Use generated demo dataset if no CSV is provided")
    args = ap.parse_args()

    if args.csv:
        df = pd.read_csv(args.csv)
        if not {"url","label"}.issubset(df.columns):
            raise ValueError("CSV must contain columns: url,label")
        df = df[["url","label"]].dropna()
    else:
        df = make_demo_dataset()
        print("No CSV provided. Trained on a generated demo dataset. Use a real labeled dataset for research-grade results.")

    metrics = train_model(df, Path(args.model_out), Path(args.metrics_out))
    print("Training complete.")
    print(pd.Series({k:v for k,v in metrics.items() if k in ['accuracy','precision','recall','f1','auc_roc']}))

if __name__ == "__main__":
    main()
