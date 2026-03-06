from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pickle
import os
import re
import traceback
import whois
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer

app = Flask(__name__)
CORS(app)  # Allow requests from Chrome extension

# ── Resolve paths relative to THIS script's location ──────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)  # parent = project root


# Check for model files in both locations:
# 1. Parent directory (local development)
# 2. Same directory as app.py (cloud deployment on Render)
def find_file(filename):
    parent_path = os.path.join(PROJECT_DIR, filename)
    local_path = os.path.join(BASE_DIR, filename)
    if os.path.exists(parent_path):
        return parent_path
    elif os.path.exists(local_path):
        return local_path
    else:
        raise FileNotFoundError(f"Cannot find {filename} in {PROJECT_DIR} or {BASE_DIR}")


MODEL_PATH = find_file('phishing_model_xgboost.pkl')
VECTORIZER_PATH = find_file('vectorizer.pkl')

print(f"Loading model from: {MODEL_PATH}")
print(f"Loading vectorizer from: {VECTORIZER_PATH}")

# ── Load saved model & vectorizer ──────────────────────────────────────────
model = pickle.load(open(MODEL_PATH, 'rb'))
vectorizer = pickle.load(open(VECTORIZER_PATH, 'rb'))

print(f"Model type: {type(model)}")
print(f"Vectorizer type: {type(vectorizer)}")

# ── NLP preprocessing objects (same as training) ───────────────────────────
tokenizer = RegexpTokenizer(r'[A-Za-z]+')
stemmer = SnowballStemmer('english')


def preprocess_url(url: str) -> str:
    """
    Replicate the exact preprocessing pipeline from the notebook:
      1. Strip http:// and https:// prefixes.
      2. Tokenize – extract only alphabetic words
      3. Stem    – reduce each token to its root form
      4. Join    – combine stemmed tokens into a single string
    """
    url = re.sub(r'^https?://', '', url)
    tokens = tokenizer.tokenize(url)
    stemmed = [stemmer.stem(word) for word in tokens]
    return ' '.join(stemmed)


# ── Heuristic Phishing Pattern Detection ───────────────────────────────────
# The ML model misses some obvious phishing patterns because words like
# "free", "winner", "claim" appear mostly in legitimate URLs in the training
# dataset. These heuristics act as a safety net to catch what the model misses.

SCAM_WORDS = [
    'free', 'winner', 'prize', 'reward', 'congratulations', 'congrats',
    'lucky', 'selected', 'gift', 'giveaway', 'offer', 'bonus',
    'claim', 'redeem', 'expire', 'urgent', 'immediately', 'act-now',
    'click-here', 'verify-now', 'confirm-now', 'update-now',
    'iphone', 'ipad', 'macbook', 'samsung', 'playstation', 'xbox',
    'bitcoin', 'crypto', 'wallet', 'investment', 'trading',
]

SUSPICIOUS_TLDS = [
    '.0tk', '.ml', '.ga', '.cf', '.gq',       # free TLDs (heavily abused)
    '.xyz', '.top', '.club', '.buzz', '.icu',  # cheap TLDs (often phishing)
    '.work', '.click', '.link', '.surf', '.rest',
    '.cam', '.monster', '.sbs',
]

IMPERSONATION_WORDS = [
    'login', 'signin', 'sign-in', 'log-in',
    'verify', 'verification', 'confirm', 'confirmation',
    'secure', 'security', 'update', 'account',
    'password', 'credential', 'authenticate',
    'paypal', 'netflix', 'apple', 'microsoft', 'amazon',
    'banking', 'bank',
]

TRUSTED_DOMAINS = [
    'google.com', 'gmail.com', 'youtube.com', 'gstatic.com',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    'github.com', 'linkedin.com', 'twitter.com', 'x.com',
    'amazon.com', 'wikipedia.org', 'reddit.com', 'stackoverflow.com',
    'apple.com', 'icloud.com', 'facebook.com', 'instagram.com',
    'netflix.com', 'paypal.com', 'whatsapp.com',
]


def compute_phishing_score(url: str, parsed_host: str) -> tuple:
    """
    Compute a heuristic phishing score (0-100) based on URL patterns.
    Returns (score, list_of_reasons).
    Higher score = more likely phishing.
    """
    score = 0
    reasons = []
    url_lower = url.lower()
    host_lower = parsed_host.lower()

    # ── Check if it's a trusted domain (skip heuristics) ──
    for domain in TRUSTED_DOMAINS:
        if host_lower == domain or host_lower.endswith('.' + domain):
            return 0, ['Trusted domain']

    # ── 1. Scam / lure words (each adds points) ──
    scam_count = 0
    for word in SCAM_WORDS:
        if word in url_lower:
            scam_count += 1
    if scam_count >= 3:
        score += 50
        reasons.append(f'{scam_count} scam/lure words detected')
    elif scam_count == 2:
        score += 30
        reasons.append(f'{scam_count} scam/lure words detected')
    elif scam_count == 1:
        score += 10
        reasons.append('Scam/lure word detected')

    # ── 2. Suspicious TLDs ──
    for tld in SUSPICIOUS_TLDS:
        if host_lower.endswith(tld):
            score += 25
            reasons.append(f'Suspicious TLD: {tld}')
            break

    # ── 3. Excessive hyphens in hostname (e.g., google-login-verify-secure.com) ──
    hyphen_count = host_lower.count('-')
    if hyphen_count >= 3:
        score += 30
        reasons.append(f'Excessive hyphens in hostname ({hyphen_count})')
    elif hyphen_count >= 2:
        score += 15
        reasons.append(f'Multiple hyphens in hostname ({hyphen_count})')

    # ── 4. IP address as hostname ──
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_lower):
        score += 35
        reasons.append('IP address used instead of domain name')

    # ── 5. Impersonation words + not the real domain ──
    impersonation_count = 0
    for word in IMPERSONATION_WORDS:
        if word in url_lower:
            impersonation_count += 1
    if impersonation_count >= 2:
        score += 20
        reasons.append(f'{impersonation_count} impersonation/phishing keywords')

    # ── 6. Very long URL (phishing URLs tend to be long) ──
    if len(url) > 100:
        score += 10
        reasons.append('Unusually long URL')

    # ── 7. HTTP instead of HTTPS ──
    if url_lower.startswith('http://') and not host_lower.startswith('localhost'):
        score += 10
        reasons.append('No HTTPS (insecure connection)')

    # ── 8. Multiple subdomains (e.g., login.secure.verify.fakesite.com) ──
    subdomain_parts = host_lower.split('.')
    if len(subdomain_parts) >= 4:
        score += 15
        reasons.append(f'Many subdomains ({len(subdomain_parts)} parts)')

    # Cap at 100
    score = min(score, 100)

    return score, reasons

# ── Real-Time Web Features ──
def get_domain_age_in_days(hostname):
    """Returns how old the domain is. Phishing sites are usually < 6 months old."""
    try:
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date
        
        # Whois can return a list or a single date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age
        return -1 # Unknown
    except Exception:
        # If WHOIS fails (e.g. domain doesn't exist or is hiding info), it's highly suspicious
        return -1

def analyze_website_content(url):
    """Downloads the HTML and looks for phishing markers. Returns (has_hidden, has_insecure_login)"""
    try:
        if not url.startswith('http'):
            url = 'http://' + url
            
        # 3-second timeout is critical for web apps
        response = requests.get(url, timeout=3)
        html_content = response.text
        
        # Look for suspicious hidden elements
        hidden_elements = "visibility: hidden" in html_content or "display: none" in html_content
            
        # Look for password fields on non-HTTPS connections
        insecure_login = "password" in html_content.lower() and not url.startswith("https")
            
        return hidden_elements, insecure_login
        
    except requests.exceptions.Timeout:
        return False, False
    except requests.exceptions.RequestException:
        return False, False


@app.route('/predict', methods=['POST'])
def predict():
    """Receive a URL, preprocess it, vectorize it, and return prediction."""
    try:
        data = request.get_json(force=True)
        url = data.get('url', '')

        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        # Guard 1: only analyse real http/https URLs
        if not url.lower().startswith(('http://', 'https://')):
            return jsonify({
                'url': url,
                'prediction': 'good',
                'confidence': 100.0,
                'note': 'Browser internal page — not a real website.',
            })

        # Extract hostname
        parsed_host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0].lower()

        # Guard 2: localhost / 127.0.0.1
        if parsed_host in ('localhost', '127.0.0.1', '::1'):
            return jsonify({
                'url': url,
                'prediction': 'good',
                'confidence': 100.0,
                'note': 'Local development server — always safe.',
            })

        import scipy.sparse as sp
        from scipy.sparse import hstack
        from urllib.parse import urlparse

        # ── 1. Create the XGBoost Structural Features Live ──
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        
        url_length = len(url)
        hostname_length = len(parsed.netloc) if parsed.netloc else 0
        path_length = len(parsed.path) if parsed.path else 0
        
        count_at = url.count('@')
        count_double_slash = url.count('//')
        count_hyphen = url.count('-')
        count_dot = url.count('.')
        count_equal = url.count('=')
        count_underscore = url.count('_')
        count_question = url.count('?')
        
        has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        is_https = 1 if url.startswith('https://') else 0
        
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly']
        is_shortened = 1 if any(short in url.lower() for short in shorteners) else 0
        
        suspicious = ['free', 'login', 'secure', 'update', 'account', 'verify', 'bank', 'winner', 'claim', 'prize']
        has_suspicious_words = 1 if any(word in url.lower() for word in suspicious) else 0

        numerical_features = sp.csr_matrix([[
            url_length, hostname_length, path_length, count_at, count_double_slash, 
            count_hyphen, count_dot, count_equal, count_underscore, count_question,
            has_ip, is_https, is_shortened, has_suspicious_words
        ]])

        # ── 2. Run the New XGBoost Model ──
        processed_text = preprocess_url(url)
        text_features = vectorizer.transform([processed_text])
        
        # Combine them exactly like we did in the Jupyter Notebook!
        combined_features = hstack([text_features, numerical_features])
        
        # XGBoost output is 0 (bad) or 1 (good) because of LabelEncoder
        prediction_num = model.predict(combined_features)[0]
        ml_prediction = 'good' if prediction_num == 1 else 'bad'

        # Get ML prediction probability
        proba = model.predict_proba(combined_features)[0]
        ml_confidence = float(round(max(proba) * 100, 1))

        # ── Run heuristic phishing score ──
        phishing_score, heuristic_reasons = compute_phishing_score(url, parsed_host)

        # ── Run Real-Time Third Party checks ──
        domain_age = get_domain_age_in_days(parsed_host)
        has_hidden_elements, has_insecure_login = analyze_website_content(url)

        real_time_warnings = []
        suspicion_level = phishing_score
        
        if domain_age != -1 and domain_age < 180: # Less than 6 months old
            suspicion_level += 50
            real_time_warnings.append(f"Domain is very new (Only {domain_age} days old)")
            
        if has_hidden_elements:
            suspicion_level += 30
            real_time_warnings.append("Suspicious hidden HTML elements detected")
            
        if has_insecure_login:
            suspicion_level += 100 # Immediate red flag
            real_time_warnings.append("Unsafe password field over unencrypted connection")

        note = ''

        all_reasons = heuristic_reasons + real_time_warnings

        # ── Combine ML + Heuristics + Real-Time checks for final decision ──

        if suspicion_level >= 50:
            # Strong heuristic/real-time suspicion overrides the ML model to 'bad'
            prediction = 'bad'
            confidence = min(suspicion_level + 10, 99.0)
            reasons_text = '; '.join(all_reasons)
            note = f'REAL-TIME ALERT: Critical phishing patterns detected: {reasons_text}'

        elif ml_prediction == 'bad':
            # ML says bad -> check if it's a trusted domain being over-flagged
            is_trusted = False
            for root in TRUSTED_DOMAINS:
                if parsed_host == root or parsed_host.endswith('.' + root):
                    is_trusted = True
                    # Trusted domain but ML flagged it
                    if 'docs.google.com' in url or 'forms' in url or 'sites.google.com' in url:
                        note = f'Warning: Hosted on {root} but flagged as suspicious. User-generated content sites can host phishing.'
                        prediction = 'bad'
                        confidence = ml_confidence
                    else:
                        prediction = 'good'
                        confidence = 65.0
                        note = f'Model flagged URL terms, but domain {root} is highly trusted. Adjusted to safe.'
                    break

            if not is_trusted:
                prediction = 'bad'
                confidence = ml_confidence

        elif ml_prediction == 'good' and suspicion_level >= 20:
            # ML says good, heuristics show moderate suspicion - warn but keep good
            prediction = 'good'
            confidence = max(ml_confidence - suspicion_level, 50.0)
            reasons_text = '; '.join(all_reasons)
            note = f'WARNING: Some suspicious patterns detected: {reasons_text}. Proceed with caution.'

        else:
            # ML says good, heuristics agree -> safe
            prediction = ml_prediction
            confidence = ml_confidence

        return jsonify({
            'url': url,
            'prediction': prediction,       # 'good' or 'bad'
            'confidence': confidence,        # e.g. 96.3
            'note': note
        })
    except Exception as e:
        import traceback
        err = traceback.format_exc()
        try:
            print(err)
        except:
            pass
        return jsonify({'error': str(e), 'traceback': str(err)}), 500


@app.route('/')
def home():
    """Serve the web scanner page where anyone can paste a URL to check."""
    return render_template('index.html')


@app.route('/health', methods=['GET'])
def health():
    """Simple health-check endpoint."""
    return jsonify({'status': 'ok', 'model_loaded': True})


if __name__ == '__main__':
    print("[*] Phishing Detection API running on http://localhost:5000")
    app.run(debug=True, port=5000, use_reloader=False)
