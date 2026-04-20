"""
The Obsidian Lens — Flask Backend (v4 Rebuild)
Minimalistic professional network forensic tool.
Two ingestion modes (Live Capture / PCAP Upload) → 49-parameter analysis →
White/Black identity categorization → SQLite fingerprint DB → Block/Unblock.
"""

import os
import sys
import json
import uuid
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, send_file

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from config import (UPLOAD_FOLDER, MODELS_FOLDER, REPORTS_FOLDER,
                     ANALYSIS_FOLDER, ALLOWED_EXTENSIONS, OTX_API_KEY)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH


# ─── CORS ────────────────────────────────────────────────────────────────

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


# ─── Analysis Cache ──────────────────────────────────────────────────────
from collections import OrderedDict

class LRUCache:
    def __init__(self, capacity=50):
        self.cache = OrderedDict()
        self.capacity = capacity
    
    def get(self, key):
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)
        return self.cache[key]
        
    def put(self, key, value):
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
            
    def delete(self, key):
        if key in self.cache:
            del self.cache[key]

    def clear(self):
        self.cache.clear()

analysis_cache = LRUCache(50)

# Thread Lock for ML Dataset concurrency
from threading import Lock
dataset_write_lock = Lock()

# ─── Helpers ─────────────────────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_analysis(analysis_id):
    data = analysis_cache.get(analysis_id)
    if data:
        return data
    cache_path = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            analysis_cache.put(analysis_id, data)
            return data
        except Exception:
            return None
    return None


def save_analysis(analysis_id, data):
    analysis_cache.put(analysis_id, data)
    cache_path = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    with open(cache_path, 'w') as f:
        json.dump(data, f, default=str)


def _valid_analysis_id(analysis_id):
    import re
    return bool(re.match(r'^[a-f0-9]{6,16}$', analysis_id))


def _build_analysis_response(analysis_id, record, otx_only=False):
    predictions = record.get('predictions', [])
    explanations = record.get('explanations', [])
    suggestions = build_analysis_suggestions(predictions)
    otx_summary = record.get('otx_summary') or summarize_otx_enrichment(predictions)
    otx_only_matches = len([
        p for p in predictions
        if int(p.get('otx_pulse_count', 0) or 0) > 0
    ])

    if otx_only:
        otx_matched = [
            p for p in predictions
            if int(p.get('otx_pulse_count', 0) or 0) > 0
        ]
        response_predictions = otx_matched if otx_matched else predictions
        response_explanations = explanations
    else:
        response_predictions = predictions
        response_explanations = explanations

    return {
        'analysis_id': analysis_id,
        'status': record.get('status', 'analyzed'),
        'metadata': record.get('metadata', {}),
        'total_flows': len(record.get('features', []) or []),
        'predictions': response_predictions,
        'explanations': response_explanations,
        'otx_summary': otx_summary,
        'suggestions': suggestions,
        'identities_created': len(set(record.get('identities_created', []))),
        'otx_only_mode': otx_only,
        'otx_only_matches': otx_only_matches,
    }


def _record_needs_reanalysis(record):
    if not record or record.get('status') != 'analyzed':
        return False

    predictions = record.get('predictions')
    if not isinstance(predictions, list) or not predictions:
        return False

    try:
        from ml.model_manager import model_exists
        if not model_exists():
            return False
    except Exception:
        return False

    return all(
        "no model" in str(pred.get('prediction') or pred.get('threat_type') or "").lower()
        for pred in predictions
    )


# ═════════════════════════════════════════════════════════════════════════
#  API: PCAP UPLOAD
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    """Upload a PCAP file for analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    analysis_id = str(uuid.uuid4())[:8]
    filename = f"{analysis_id}_{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        print(f"[UPLOAD] Saved: {filename} ({file_size} bytes)")

        save_analysis(analysis_id, {
            'id': analysis_id,
            'filename': file.filename,
            'filepath': filepath,
            'status': 'uploaded',
            'source': 'upload',
            'uploaded_at': datetime.now().isoformat(),
        })

        return jsonify({
            'analysis_id': analysis_id,
            'filename': file.filename,
            'status': 'uploaded',
        })
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


# ═════════════════════════════════════════════════════════════════════════
#  API: LIVE CAPTURE
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/capture/interfaces', methods=['GET'])
def list_interfaces():
    from core.live_capture import get_interfaces
    return jsonify({'interfaces': get_interfaces()})


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    from core.live_capture import start_capture as _start
    data = request.get_json(silent=True) or {}
    result = _start(
        interface=data.get('interface'),
        duration=data.get('duration', 120),
        packet_count=data.get('packet_count', 3000),
        mode=data.get('mode', 'live'),
    )
    return jsonify(result)


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    from core.live_capture import stop_capture as _stop
    result = _stop()

    data = request.get_json(silent=True) or {}
    mode = data.get('mode', 'standard')
    source_val = 'otx_capture' if mode == 'otx' else 'live_capture'

    output_file = result.get('output_file')

    if output_file and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        analysis_id = str(uuid.uuid4())[:8]
        filename = os.path.basename(output_file)

        save_analysis(analysis_id, {
            'id': analysis_id,
            'filename': filename,
            'filepath': output_file,
            'status': 'uploaded',
            'source': source_val,
            'packets_captured': result.get('packets_captured', 0),
            'capture_duration': result.get('duration', 0),
            'uploaded_at': datetime.now().isoformat(),
        })

        result['analysis_id'] = analysis_id

    return jsonify(result)

@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    from core.live_capture import get_capture_status
    return jsonify(get_capture_status())

@app.route('/api/analysis/<analysis_id>', methods=['DELETE'])
def delete_analysis_record(analysis_id):
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    cache_path = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    if os.path.exists(cache_path):
        os.remove(cache_path)
    analysis_cache.delete(analysis_id)
        
    return jsonify({'success': True}), 200


# ═════════════════════════════════════════════════════════════════════════
#  API: HARD SYSTEM RESET
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/reset', methods=['POST'])
def hard_reset():
    """Wipe all uploads, analysis cache, identity DB, and reports. Non-reversible."""
    import shutil
    errors = []

    # 1. Wipe analysis cache (in-memory + disk)
    try:
        analysis_cache.clear()
        if os.path.isdir(ANALYSIS_FOLDER):
            for f in os.listdir(ANALYSIS_FOLDER):
                fp = os.path.join(ANALYSIS_FOLDER, f)
                try:
                    os.remove(fp)
                except Exception as e:
                    errors.append(f"cache:{f}:{e}")
    except Exception as e:
        errors.append(f"analysis_folder:{e}")

    # 2. Wipe uploaded PCAPs
    try:
        if os.path.isdir(UPLOAD_FOLDER):
            for f in os.listdir(UPLOAD_FOLDER):
                fp = os.path.join(UPLOAD_FOLDER, f)
                try:
                    os.remove(fp)
                except Exception as e:
                    errors.append(f"upload:{f}:{e}")
    except Exception as e:
        errors.append(f"upload_folder:{e}")

    # 3. Wipe generated PDF reports
    try:
        if os.path.isdir(REPORTS_FOLDER):
            for f in os.listdir(REPORTS_FOLDER):
                fp = os.path.join(REPORTS_FOLDER, f)
                try:
                    if os.path.isfile(fp):
                        os.remove(fp)
                except Exception as e:
                    errors.append(f"report:{f}:{e}")
    except Exception as e:
        errors.append(f"reports_folder:{e}")

    # 4. Wipe identity database — drop all tables and recreate schema
    try:
        import sqlite3
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'obsidian_identities.db')
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]
            for table in tables:
                cur.execute(f"DELETE FROM {table}")
            conn.commit()
            conn.close()
    except Exception as e:
        errors.append(f"identity_db:{e}")

    print(f"[HARD RESET] System wiped. Errors: {errors or 'None'}")
    return jsonify({
        'success': True,
        'errors': errors,
        'message': 'System hard reset complete. All data has been purged.'
    }), 200

# ═════════════════════════════════════════════════════════════════════════
#  XAI HEURISTIC MAPPINGS
# ═════════════════════════════════════════════════════════════════════════

XAI_INSIGHTS_DICT = {
    'flow_duration': 'Abnormally long flow duration implies a persistent connection, typical of Remote Access Trojans (RATs) or Command & Control beacons.',
    'fwd_packet': 'High volume or erratic forward packet variance indicates an outbound data exfiltration attempt or aggressive request flooding.',
    'bwd_packet': 'Large backward packet anomalies suggest the system is actively fetching heavy secondary payloads from an external staging server.',
    'flow_bytes': 'A spike in network throughput matches expected bandwidth saturation techniques used in volumetric DDoS attacks.',
    'fin_flag': 'Rapid accumulation of FIN flags signifies constant tearing down of connections, typical in exhaustive port scanning or stealth network mapping.',
    'down/up': 'An imbalanced connection ratio strongly suggests an automated botnet script rigidly fetching commands without standard human interaction delays.',
    'init_win': 'Anomalous initial window bytes are common in forged TCP handshakes used to bypass standard firewall state tracking.',
    'iat': 'Irregular inter-arrival timing (IAT) signatures reveal algorithmic heartbeats attempting to mimic human browsing behavior to evade detection.',
    'bwd_pkt_len_max': 'Anomalous backward packet payload size indicating potential unauthorized data ingress from an external vector.',
    'flow_packets_per_sec': 'Abnormal volume geometry implies automated high-throughput data channeling or brute force tunneling.',
    'syn_flag': 'Spike in SYN flags directly correlates with aggressive network scanner reconnaissance and enumeration operations.'
}

def generate_insights(top_features, is_malicious, threat_type):
    insights = []
    base_verdict = f'a confirmed {threat_type}' if is_malicious else 'Safe Network Noise'
    
    for feature in top_features:
        if isinstance(feature, dict):
            f_name = feature.get('feature') or feature.get('name') or 'Unknown Feature'
            weight = float(feature.get('contribution', feature.get('importance', 0.0)) or 0.0)
        else:
            f_name, weight = feature

        insight_found = False
        f_lower = f_name.lower().replace(' ', '_')
        for key, text in XAI_INSIGHTS_DICT.items():
            if key in f_lower:
                insights.append(f"[{f_name}] ({weight*100:.1f}% Weight): {text} This mathematical anomaly heavily forced the AI to classify this as {base_verdict}.")
                insight_found = True
                break
        if not insight_found:
             insights.append(f"[{f_name}] ({weight*100:.1f}% Weight): The neural network identified extreme structural variance in this parameter while forming the {base_verdict} profile.")
    return insights


def build_analysis_suggestions(predictions):
    malicious = [p for p in predictions if p.get('is_malicious')]
    threats = list({p.get('threat_type', '') for p in malicious if p.get('threat_type')})
    suggestions = []

    if malicious:
        suggestions.append({
            'icon': '[!]',
            'title': 'Immediate Review',
            'text': f"{len(malicious)} malicious flow{'s' if len(malicious) > 1 else ''} detected. Immediate investigation of flagged identities is recommended."
        })
        if threats:
            suggestions.append({
                'icon': '[WARN]',
                'title': 'Threat Attribution',
                'text': f"Detected threat types: {', '.join(threats)}. Cross-reference with MITRE ATT&CK for tactic and technique attribution."
            })
        if any('ddos' in (t.lower() or '') for t in threats):
            suggestions.append({
                'icon': '[SEC]',
                'title': 'DDoS Mitigation',
                'text': 'DDoS behavior detected. Consider upstream rate-limiting and temporary sinkhole or blackhole controls for persistent sources.'
            })
        if any(k in ' '.join(threats).lower() for k in ['botnet', 'c2', 'beacon', 'rat']):
            suggestions.append({
                'icon': '[INV]',
                'title': 'C2 / Botnet Response',
                'text': 'Potential beaconing or botnet behavior detected. Isolate affected endpoints and perform host-level memory and persistence checks.'
            })
        suggestions.append({
            'icon': '[DOC]',
            'title': 'Documentation',
            'text': 'Export the PDF report to preserve top influential features, XAI insights, and analyst-ready evidence.'
        })
    else:
        suggestions.append({
            'icon': '[OK]',
            'title': 'Traffic Normal',
            'text': 'No malicious flows detected. Current traffic aligns with expected behavioral baselines.'
        })
        suggestions.append({
            'icon': '[ARCH]',
            'title': 'Baseline Archival',
            'text': 'Archive this capture as a baseline reference for future anomaly comparison.'
        })

    vpn_flows = [p for p in predictions if p.get('is_vpn')]
    if vpn_flows:
        suggestions.append({
            'icon': '[VPN]',
            'title': 'VPN-Masked Flows',
            'text': f"{len(vpn_flows)} VPN-masked flow{'s' if len(vpn_flows) > 1 else ''} identified via behavioral fingerprinting."
        })

    return suggestions


def calculate_hybrid_threat_score(ml_confidence, otx_reputation, is_malicious=False):
    behavioral_score = round(float(ml_confidence or 0.0), 4)
    otx_score = round(float((otx_reputation or {}).get('otx_score', 0.0) or 0.0), 4)
    hybrid_score = round((behavioral_score * 0.7) + (otx_score * 0.3), 4)

    if (otx_reputation or {}).get('pulse_count', 0) > 3:
        verdict = 'confirmed_malicious'
    elif hybrid_score >= 0.7 or is_malicious:
        verdict = 'high_risk'
    elif hybrid_score >= 0.4 or (otx_reputation or {}).get('malicious'):
        verdict = 'suspicious'
    else:
        verdict = 'benign'

    return {
        'behavioral_score': behavioral_score,
        'otx_score': otx_score,
        'hybrid_score': hybrid_score,
        'verdict': verdict,
    }


def summarize_otx_enrichment(predictions):
    enriched = [p for p in predictions if p.get('otx_reputation', {}).get('reputation_available')]
    malicious = [p for p in enriched if p.get('otx_malicious')]
    pulse_names = []
    tags = []

    for pred in malicious:
        pulse_names.extend(pred.get('otx_pulse_names', []))
        tags.extend(pred.get('otx_tags', []))

    def _uniq(values):
        seen = set()
        result = []
        for value in values:
            key = str(value).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            result.append(str(value).strip())
        return result

    return {
        'provider': 'AlienVault OTX',
        'lookups_performed': len(enriched),
        'malicious_matches': len(malicious),
        'max_pulse_count': max((p.get('otx_pulse_count', 0) for p in malicious), default=0),
        'pulse_names': _uniq(pulse_names),
        'tags': _uniq(tags),
    }


def select_primary_explanation(explanations, predictions):
    if not explanations:
        return None, None

    ranked = sorted(
        range(len(explanations)),
        key=lambda idx: (
            predictions[idx].get('is_malicious', False) if idx < len(predictions) else False,
            predictions[idx].get('confidence', 0.0) if idx < len(predictions) else 0.0,
        ),
        reverse=True,
    )
    best_index = ranked[0]
    return explanations[best_index], best_index


def build_xai_summary(explanations, predictions):
    primary_explanation, primary_index = select_primary_explanation(explanations, predictions)
    if not primary_explanation:
        return []

    prediction = predictions[primary_index] if primary_index is not None and primary_index < len(predictions) else {}
    threat_type = prediction.get('threat_type', 'Unknown')
    is_malicious = prediction.get('is_malicious', False)
    top_features = primary_explanation.get('top_features', [])[:10]

    return [{
        'flow_index': primary_index,
        'prediction': primary_explanation.get('prediction', prediction.get('threat_type', 'Unknown')),
        'confidence': primary_explanation.get('confidence', prediction.get('confidence', 0.0)),
        'top_features': top_features,
        'feature_details': primary_explanation.get('feature_details', top_features),
        'explanation_text': primary_explanation.get('explanation_text', ''),
        'insights': generate_insights(top_features[:5], is_malicious, threat_type),
    }]


def build_heuristic_xai_summary(features, predictions=None):
    predictions = predictions or []
    if not features:
        return []

    feature_row = features[0] if isinstance(features[0], dict) else {}
    identifier_fields = {
        'flow_key', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'mac_address', 'ja3_hash', 'protocol'
    }

    scored_features = []
    for name, value in feature_row.items():
        if name in identifier_fields or isinstance(value, bool):
            continue
        if not isinstance(value, (int, float)):
            continue

        abs_value = abs(float(value))
        if abs_value <= 0:
            continue

        lowered = name.lower()
        priority_boost = 2.0 if any(key in lowered for key in XAI_INSIGHTS_DICT.keys()) else 1.0
        score = priority_boost * (abs_value if abs_value < 1 else min(abs_value, 1_000_000) ** 0.5)
        scored_features.append({
            'feature': name,
            'importance': 0.0,
            'value': round(float(value), 6),
            'contribution': score,
        })

    if not scored_features:
        return []

    scored_features.sort(key=lambda item: item['contribution'], reverse=True)
    top_features = scored_features[:10]
    total = sum(item['contribution'] for item in top_features) or 1.0
    for item in top_features:
        item['importance'] = round(item['contribution'] / total, 4)
        item['contribution'] = round(item['importance'], 4)

    primary_prediction = predictions[0] if predictions else {}
    threat_type = primary_prediction.get('threat_type', 'Observed Traffic')
    is_malicious = primary_prediction.get('is_malicious', False)

    return [{
        'flow_index': 0,
        'prediction': primary_prediction.get('prediction', threat_type),
        'confidence': round(primary_prediction.get('confidence', 0.0), 4),
        'top_features': top_features,
        'feature_details': top_features,
        'explanation_text': 'Heuristic XAI summary generated from extracted network features because model-driven explanation data was unavailable.',
        'insights': generate_insights(top_features[:5], is_malicious, threat_type),
    }]


def ensure_explanations(record):
    predictions = record.get('predictions', [])
    explanations = record.get('explanations', [])
    features = record.get('features', [])

    if explanations:
        return explanations

    try:
        from ml.model_manager import load_model
        import pandas as pd
        from xai.explainer import explain_batch

        if not features:
            return explanations

        classifier, preprocessor, _ = load_model()
        features_df = pd.DataFrame(features)
        X = preprocessor.transform(features_df)
        per_flow_explanations = explain_batch(classifier, X)
        explanations = build_xai_summary(per_flow_explanations, predictions)
        record['explanations'] = explanations
    except Exception:
        explanations = build_heuristic_xai_summary(features, predictions)
        if explanations:
            record['explanations'] = explanations

    return explanations


def _normalize_features_df_for_dataset(df, include_label=True):
    """Return a DataFrame with consistent columns for dataset/rl CSV writes.

    Ensures all FEATURE_COLUMNS are present (filled with 0), drops
    non-ML identifier columns, and orders columns consistently.
    """
    try:
        from core.feature_extractor import FEATURE_COLUMNS
        import numpy as np
    except Exception:
        return df

    df2 = df.copy()

    # Drop identifier columns that should not be in ML CSVs
    df2 = df2.drop(columns=['flow_key', 'protocol', 'ja3_hash', 'mac_address',
                            'src_port', 'dst_port'], errors='ignore')

    # Ensure all FEATURE_COLUMNS exist
    for col in FEATURE_COLUMNS:
        if col not in df2.columns:
            df2[col] = 0

    # If label requested, keep or create label column
    if include_label:
        if 'label' not in df2.columns:
            df2['label'] = 'unknown'

    # Order columns: FEATURE_COLUMNS then label (if present) then any extras
    ordered = FEATURE_COLUMNS[:] + (['label'] if include_label else [])
    remaining = [c for c in df2.columns if c not in ordered]
    df2 = df2[ordered + remaining]

    # Clean numeric columns
    try:
        df2[FEATURE_COLUMNS] = df2[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0).astype(float)
    except Exception:
        pass

    return df2

# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/analyze/<analysis_id>', methods=['GET'])
def run_analysis(analysis_id):
    """
    Full pipeline: Parse PCAP → Extract 49 features → Classify →
    Categorize White/Black → Store identities in SQLite DB.
    """
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404
    otx_only = str(request.args.get('otx_only', '')).lower() in {'1', 'true', 'yes', 'on'}

    if record.get('status') == 'analyzed' and record.get('predictions') is not None and not _record_needs_reanalysis(record):
        return jsonify(_build_analysis_response(analysis_id, record, otx_only=otx_only))

    try:
        from core.pcap_parser import parse_pcap
        from core.feature_extractor import extract_features
        from core.flow_analyzer import analyze_flows
        from core.identity_db import upsert_identity
        import pandas as pd

        filepath = record['filepath']
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        # Step 1: Parse PCAP
        print(f"[ANALYZE] Parsing {analysis_id}...")
        parsed = parse_pcap(filepath)

        if parsed['metadata']['total_packets'] == 0:
            raise ValueError('No packets found in PCAP file.')

        # Step 2: Extract 49 behavioral features
        print(f"[ANALYZE] Extracting 49-parameter behavioral features...")
        features_df = extract_features(parsed)

        if features_df.empty:
            raise ValueError('No flows could be extracted.')

        # Step 3: Flow analysis
        flow_analysis = analyze_flows(parsed)

        # Step 4: Classify (if model exists)
        predictions = []
        explanations = []
        identities_created = []

        try:
            from ml.model_manager import load_model
            from xai.explainer import explain_batch
            from core.otx_enrichment import check_ip_reputation
            classifier, preprocessor, model_meta = load_model()

            X = preprocessor.transform(features_df)
            results = classifier.predict_with_details(X)
            per_flow_explanations = explain_batch(classifier, X)

            # Step 5: Store each classified flow as an identity in DB
            for i, pred in enumerate(results):
                row = features_df.iloc[i]
                src_ip = row.get('src_ip', '')
                dst_ip = row.get('dst_ip', '')
                ja3_hash = ''

                # Determine category
                if pred['is_malicious']:
                    category = 'black'
                    threat_type = pred['threat_type']
                else:
                    category = 'white'
                    threat_type = 'Safe Traffic'

                otx_result = check_ip_reputation(src_ip, api_key=OTX_API_KEY) if src_ip else {
                    'reputation_available': False,
                    'malicious': False,
                    'pulse_count': 0,
                    'pulse_names': [],
                    'malware_tags': [],
                    'country_name': '',
                    'last_seen': '',
                    'intel_severity': 'none',
                    'threat_reputation_summary': 'No source IP available for OTX lookup.',
                    'otx_score': 0.0,
                }

                pulse_count = int(otx_result.get('pulse_count', 0) or 0)
                otx_malicious = bool(otx_result.get('malicious'))
                raw_ml_confidence = float(pred.get('confidence', 0.0) or 0.0)
                confidence_bonus = 0.0
                if otx_malicious:
                    confidence_bonus = 0.05
                if pulse_count > 3:
                    confidence_bonus = max(confidence_bonus, 0.12)

                pred['confidence'] = round(min(0.99, raw_ml_confidence + confidence_bonus), 4)
                pred['otx_reputation'] = otx_result
                pred['otx_pulse_count'] = pulse_count
                pred['otx_tags'] = otx_result.get('malware_tags', [])
                pred['otx_pulse_names'] = otx_result.get('pulse_names', [])
                pred['otx_country'] = otx_result.get('country_name', '')
                pred['otx_asn'] = otx_result.get('asn', '')
                pred['otx_last_seen'] = otx_result.get('last_seen', '')
                pred['otx_malicious'] = otx_malicious
                pred['threat_intel_source'] = 'AlienVault OTX' if otx_result.get('reputation_available') else ''

                hybrid_scores = calculate_hybrid_threat_score(
                    raw_ml_confidence,
                    otx_result,
                    is_malicious=pred.get('is_malicious', False),
                )
                pred.update(hybrid_scores)
                pred['confidence_boost'] = round(confidence_bonus, 4)

                if otx_malicious:
                    pred['otx_insight'] = (
                        "Global OTX intelligence confirms this IP is associated with known malicious campaigns."
                    )

                if pulse_count > 3:
                    pred['is_malicious'] = True
                    pred['category'] = 'Malicious'
                    pred['black_identity_candidate'] = True
                    category = 'black'
                    if threat_type == 'Safe Traffic':
                        threat_type = 'OTX Confirmed Malicious Infrastructure'
                    else:
                        threat_type = f"OTX Confirmed {threat_type}"
                    pred['threat_type'] = threat_type

                # Build 10D behavior vector from most stable behavioral features
                # 10 most stable behavioral features for cross-device identity matching
                # Must use EXACT column names from feature_extractor.py FEATURE_COLUMNS
                BEHAVIOR_FEATURES = [
                    'flow_duration', 'iat_mean', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
                    'flow_bytes_per_sec', 'flow_packets_per_sec', 'fwd_iat_mean',
                    'bwd_iat_mean', 'down_up_ratio', 'active_time_mean'
                ]
                bvec = []
                for f in BEHAVIOR_FEATURES:
                    # Try exact match, then partial match
                    val = None
                    for col in features_df.columns:
                        if f in col.lower().replace(' ', '_'):
                            val = row.get(col, 0.0)
                            break
                    bvec.append(float(val) if val is not None else 0.0)

                identity_id = upsert_identity(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    category=category,
                    threat_type=threat_type,
                    confidence=pred['confidence'],
                    ja3_hash=ja3_hash,
                    analysis_id=analysis_id,
                    behavior_vector=bvec,
                    full_features=row.to_dict(),
                    otx_pulse_count=pulse_count,
                    otx_threat_tags=otx_result.get('malware_tags', []),
                    otx_last_seen=otx_result.get('last_seen', ''),
                    global_reputation=otx_result.get('intel_severity', 'unknown'),
                    confidence_boost_source='AlienVault OTX' if confidence_bonus > 0 else ''
                )

                pred['identity_id'] = identity_id
                pred['src_ip'] = src_ip
                pred['dst_ip'] = dst_ip
                identities_created.append(identity_id)

            predictions = results
            explanations = build_xai_summary(per_flow_explanations, predictions)

        except FileNotFoundError:
            from core.otx_enrichment import check_ip_reputation
            predictions = []
            for i in range(len(features_df)):
                row = features_df.iloc[i]
                src_ip = row.get('src_ip', '')
                dst_ip = row.get('dst_ip', '')
                
                otx_result = check_ip_reputation(src_ip, api_key=OTX_API_KEY) if src_ip else {
                    'reputation_available': False,
                    'malicious': False,
                    'pulse_count': 0,
                    'pulse_names': [],
                    'malware_tags': [],
                    'country_name': '',
                    'last_seen': '',
                    'intel_severity': 'none',
                    'threat_reputation_summary': 'No source IP available for OTX lookup.',
                    'otx_score': 0.0,
                }
                
                pulse_count = int(otx_result.get('pulse_count', 0) or 0)
                otx_malicious = bool(otx_result.get('malicious'))
                
                category = 'white'
                threat_type = 'Unclassified (No Model)'
                is_malicious = False
                
                if pulse_count > 3:
                    is_malicious = True
                    category = 'black'
                    threat_type = 'OTX Confirmed Malicious Infrastructure'

                placeholder_prediction = {
                    'prediction': threat_type,
                    'confidence': 0.99 if is_malicious else 0.0,
                    'behavioral_score': 0.0,
                    'otx_score': float(otx_result.get('otx_score', 0.0) or 0.0),
                    'hybrid_score': float(otx_result.get('otx_score', 0.0) or 0.0),
                    'verdict': 'confirmed_malicious' if pulse_count > 3 else ('suspicious' if otx_malicious else 'benign'),
                    'probabilities': {},
                    'category': 'Malicious' if is_malicious else 'Normal',
                    'is_vpn': False,
                    'is_malicious': is_malicious,
                    'threat_type': threat_type,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'otx_reputation': otx_result,
                    'otx_pulse_count': pulse_count,
                    'otx_tags': otx_result.get('malware_tags', []),
                    'otx_pulse_names': otx_result.get('pulse_names', []),
                    'otx_country': otx_result.get('country_name', ''),
                    'otx_asn': otx_result.get('asn', ''),
                    'otx_last_seen': otx_result.get('last_seen', ''),
                    'otx_malicious': otx_malicious,
                    'threat_intel_source': 'AlienVault OTX' if otx_result.get('reputation_available') else ''
                }

                if pulse_count > 3:
                     placeholder_prediction['black_identity_candidate'] = True

                identity_id = upsert_identity(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    category=category,
                    threat_type=threat_type,
                    confidence=placeholder_prediction['confidence'],
                    analysis_id=analysis_id,
                    full_features=row.to_dict(),
                    otx_pulse_count=pulse_count,
                    otx_threat_tags=otx_result.get('malware_tags', []),
                    otx_last_seen=otx_result.get('last_seen', ''),
                    global_reputation=otx_result.get('intel_severity', 'unknown')
                )
                placeholder_prediction['identity_id'] = identity_id
                predictions.append(placeholder_prediction)
                identities_created.append(identity_id)

            explanations = build_heuristic_xai_summary(
                features_df.to_dict(orient='records'),
                predictions,
            )

        otx_summary = summarize_otx_enrichment(predictions)

        # Save results
        record.update({
            'status': 'analyzed',
            'metadata': parsed['metadata'],
            'flow_analysis': flow_analysis,
            'features': features_df.to_dict(orient='records'),
            'predictions': predictions,
            'explanations': explanations,
            'otx_summary': otx_summary,
            'identities_created': identities_created,
            'analyzed_at': datetime.now().isoformat(),
        })
        record.pop('error_message', None)

        save_analysis(analysis_id, record)
        print(f"[ANALYZE] Complete: {len(features_df)} flows, {len(identities_created)} identities")

        return jsonify(_build_analysis_response(analysis_id, record, otx_only=otx_only))

    except Exception as e:
        print(f"[ERROR] Analysis failed: {str(e)}")
        print(traceback.format_exc())
        if record:
            record['status'] = 'failed'
            record['error_message'] = str(e)
            record['analyzed_at'] = datetime.now().isoformat()
            save_analysis(analysis_id, record)
        return jsonify({'error': str(e)}), 500


# ═════════════════════════════════════════════════════════════════════════
#  API: IDENTITY DATABASE
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/identities', methods=['GET'])
def list_identities():
    """Get all tracked identities (White and Black users)."""
    from core.identity_db import get_all_identities
    identities = get_all_identities()

    white = [i for i in identities if i['category'] == 'white']
    black = [i for i in identities if i['category'] == 'black']

    return jsonify({
        'total': len(identities),
        'white_users': white,
        'black_users': black,
    })


@app.route('/api/identities/<int:identity_id>', methods=['GET'])
def get_identity_detail(identity_id):
    """Get full details for a specific identity."""
    from core.identity_db import get_identity
    identity = get_identity(identity_id)
    if not identity:
        return jsonify({'error': 'Identity not found'}), 404
    return jsonify(identity)


@app.route('/api/identities/<int:identity_id>/block', methods=['POST'])
def block_identity_endpoint(identity_id):
    """Block a malicious identity from the network by deploying real Windows Firewall rules."""
    from core.identity_db import block_identity, get_identity
    identity = get_identity(identity_id)
    if not identity:
        return jsonify({'error': 'Identity not found'}), 404
    
    # Actually block through Windows Firewall! (Elevated)
    import subprocess
    block_success = []
    for ip in identity.get('associated_ips', []):
        try:
            rule_name = f"OBSIDIAN_BLOCK_{ip}"
            cmd_in = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={rule_name}', 'dir=in', 'action=block', f'remoteip={ip}']
            cmd_out = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={rule_name}_OUT', 'dir=out', 'action=block', f'remoteip={ip}']
            subprocess.run(cmd_in, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(cmd_out, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            block_success.append(ip)
        except Exception as e:
            print(f"Failed to elevate firewall block for {ip}: {e}")

    block_identity(identity_id)
    return jsonify({'status': 'blocked', 'identity_id': identity_id, 'firewall_blocked_ips': block_success})


@app.route('/api/identities/<int:identity_id>/unblock', methods=['POST'])
def unblock_identity_endpoint(identity_id):
    """Unblock an identity."""
    from core.identity_db import unblock_identity, get_identity
    identity = get_identity(identity_id)
    if not identity:
        return jsonify({'error': 'Identity not found'}), 404
        
    import subprocess
    unblock_success = []
    for ip in identity.get('associated_ips', []):
        try:
            rule_name = f"OBSIDIAN_BLOCK_{ip}"
            cmd_in = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
            cmd_out = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}_OUT']
            subprocess.run(cmd_in, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(cmd_out, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            unblock_success.append(ip)
        except Exception as e:
            print(f"Failed to elevate firewall unblock for {ip}: {e}")
            
    unblock_identity(identity_id)
    return jsonify({'status': 'unblocked', 'identity_id': identity_id, 'firewall_unblocked_ips': unblock_success})


# ═════════════════════════════════════════════════════════════════════════
#  API: NETWORK HEALTH
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/network-health', methods=['GET'])
def network_health():
    """Get network health score and summary stats."""
    from core.identity_db import get_network_health
    return jsonify(get_network_health())


# ═════════════════════════════════════════════════════════════════════════
#  API: TRAIN MODEL
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/train', methods=['POST'])
def train_model():
    """Train the behavioral fingerprinting model on the real-world CICIDS2017 dataset."""
    try:
        import pandas as pd
        from ml.real_dataset_loader import load_real_dataset
        from ml.preprocessor import Preprocessor
        from ml.classifier import BehavioralClassifier
        from ml.model_manager import save_model

        data = request.get_json(silent=True) or {}
        max_rows = data.get('max_rows', 100000)  # Default: 100k rows for fast training

        print("[TRAIN] Loading real-world CICIDS2017 dataset...")
        df = load_real_dataset(max_rows=max_rows)

        # Merge with any accumulated RL feedback data
        rl_path = os.path.join(BASE_DIR, 'data', 'rl_feedback.csv')
        if os.path.exists(rl_path):
            rl_df = pd.read_csv(rl_path)
            df = pd.concat([df, rl_df], ignore_index=True)
            print(f"[TRAIN] Merged {len(rl_df)} RL feedback rows into training set.")

        preprocessor = Preprocessor()
        X, y = preprocessor.fit_transform(df)

        classifier = BehavioralClassifier()
        metrics = classifier.train(X, y)

        save_model(classifier, preprocessor, metadata=metrics)

        return jsonify({
            'status': 'trained',
            'metrics': metrics,
            'dataset_size': len(df),
            'data_source': 'CICIDS2017 real-world + RL feedback'
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/feedback/<analysis_id>', methods=['POST'])
def apply_feedback(analysis_id):
    """
    Continuous Learning: 
    Take user feedback (a new label) for an analysis, append its features 
    to the persistent dataset, and instantly retrain the model.
    """
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404

    data = request.get_json(silent=True) or {}
    new_label = data.get('label')
    if not new_label:
        return jsonify({'error': 'Missing label'}), 400

    # Normalize analyst-provided label to canonical AttackType values when possible
    try:
        from ml.labels import AttackType
        norm_enum = AttackType.from_string(new_label)
        if norm_enum:
            new_label = norm_enum.value
    except Exception:
        pass

    try:
        import pandas as pd
        from core.pcap_parser import parse_pcap
        from core.feature_extractor import extract_features
        
        parsed = parse_pcap(record['filepath'])
        features_df = extract_features(parsed)
        
        if features_df.empty:
            return jsonify({'error': 'No flows to learn from in this PCAP'}), 400
            
        # Assign the analyst-confirmed label
        features_df['label'] = new_label
        
        # Drop non-ML identifier columns
        features_df = features_df.drop(
            columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'mac_address',
                     'ja3_hash', 'flow_key', 'protocol'], errors='ignore'
        )

        # Append to RL feedback layer (separate from the real-world base dataset)
        os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
        rl_path = os.path.join(BASE_DIR, 'data', 'rl_feedback.csv')
        try:
            df_to_write = _normalize_features_df_for_dataset(features_df, include_label=True)
        except Exception:
            df_to_write = features_df
        df_to_write.to_csv(rl_path, mode='a', header=not os.path.exists(rl_path), index=False)

        # Retrain: real-world dataset + all accumulated RL feedback
        from ml.real_dataset_loader import load_real_dataset
        from ml.preprocessor import Preprocessor
        from ml.classifier import BehavioralClassifier
        from ml.model_manager import save_model

        with dataset_write_lock:
            base_df = load_real_dataset(max_rows=80000)
            rl_df = pd.read_csv(rl_path)
            full_df = pd.concat([base_df, rl_df], ignore_index=True)

            preprocessor = Preprocessor()
            X, y = preprocessor.fit_transform(full_df)
            classifier = BehavioralClassifier()
            metrics = classifier.train(X, y)
            save_model(classifier, preprocessor, metadata=metrics)
        
        return jsonify({
            'status': 'success',
            'message': f'Model retrained with {len(features_df)} new flows as "{new_label}"',
            'rl_feedback_total': len(rl_df),
            'training_set_size': len(full_df),
            'metrics': metrics
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/feedback/bulk', methods=['POST'])
def apply_bulk_feedback():
    """
    Continuous Learning (Batch Engine):
    Process multiple analyses safely in a single thread to avoid CSV/PKL race conditions.
    """
    data = request.get_json(silent=True) or {}
    new_label = data.get('label')
    analysis_ids = data.get('analysis_ids', [])
    
    if not new_label or not analysis_ids:
        return jsonify({'error': 'Missing label or analysis IDs'}), 400
    # Normalize provided label to canonical AttackType when possible
    try:
        from ml.labels import AttackType
        norm_enum = AttackType.from_string(new_label)
        if norm_enum:
            new_label = norm_enum.value
    except Exception:
        pass
        
    try:
        import pandas as pd
        from core.pcap_parser import parse_pcap
        from core.feature_extractor import extract_features
        
        all_features = []
        
        for ans_id in analysis_ids:
            record = get_analysis(ans_id)
            if not record: continue
            
            parsed = parse_pcap(record['filepath'])
            f_df = extract_features(parsed)
            if not f_df.empty:
                all_features.append(f_df)
                
        if not all_features:
            return jsonify({'error': 'No valid flows extracted from selected captures.'}), 400
            
        # Combine all features
        features_df = pd.concat(all_features, ignore_index=True)
        features_df['label'] = new_label
        
        # Clean addresses
        if 'src_ip' in features_df.columns:
            features_df = features_df.drop(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'mac_address', 'ja3_hash'], errors='ignore')

        # Append to CSV precisely once
        dataset_path = os.path.join(BASE_DIR, 'data', 'training_data.csv')
        
        with dataset_write_lock:
            if not os.path.exists(dataset_path):
                from ml.dataset_generator import generate_dataset
                base_df = generate_dataset(n_samples_per_profile=100)
                base_df.to_csv(dataset_path, index=False)
                
            try:
                df_to_write = _normalize_features_df_for_dataset(features_df, include_label=True)
            except Exception:
                df_to_write = features_df
            df_to_write.to_csv(dataset_path, mode='a', header=not os.path.exists(dataset_path), index=False)
    
            # Trigger Single Retrain — sliding window over last 5000 rows to keep model fresh
            from ml.preprocessor import Preprocessor
            from ml.classifier import BehavioralClassifier
            from ml.model_manager import save_model
    
            full_df = pd.read_csv(dataset_path)
            
            # Cap to most recent 5000 rows — newer data should dominate
            SLIDING_WINDOW = 5000
            if len(full_df) > SLIDING_WINDOW:
                full_df = full_df.tail(SLIDING_WINDOW).reset_index(drop=True)
                print(f"[RL] Using sliding window: last {SLIDING_WINDOW} samples")

            # Label distribution for analyst feedback
            label_counts = full_df['label'].value_counts().to_dict() if 'label' in full_df.columns else {}
            print(f"[RL] Label distribution: {label_counts}")

            preprocessor = Preprocessor()
            X, y = preprocessor.fit_transform(full_df)
    
            classifier = BehavioralClassifier()
            metrics = classifier.train(X, y)
            save_model(classifier, preprocessor, metadata=metrics)
        
        return jsonify({
            'status': 'success',
            'message': f'Model batch-retrained with {len(features_df)} combined flows.',
            'dataset_size': len(full_df),
            'metrics': metrics
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/models', methods=['GET'])
def list_models():
    """Get info about the current trained model."""
    from ml.model_manager import model_exists, get_model_info
    return jsonify({
        'model_exists': model_exists(),
        'model': get_model_info(),
    })


# ═════════════════════════════════════════════════════════════════════════
#  API: DASHBOARD SUMMARY
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/summary', methods=['GET'])
def dashboard_summary():
    """Combined summary for the professional dashboard."""
    from ml.model_manager import model_exists, get_model_info
    from core.identity_db import get_network_health, get_all_identities

    health = get_network_health()
    identities = get_all_identities()

    # Gather recent analyses
    analyses = []
    if os.path.exists(ANALYSIS_FOLDER):
        # Sort files by modification time (newest first)
        files = [f for f in os.listdir(ANALYSIS_FOLDER) if f.endswith('.json')]
        files.sort(key=lambda x: os.path.getmtime(os.path.join(ANALYSIS_FOLDER, x)), reverse=True)
        
        for f in files[:10]:
            try:
                with open(os.path.join(ANALYSIS_FOLDER, f), 'r') as fh:
                    data = json.load(fh)
                analyses.append({
                    'id': data.get('id', f.replace('.json', '')),
                    'filename': data.get('filename', 'unknown'),
                    'status': data.get('status', 'unknown'),
                    'source': data.get('source', 'upload'),
                    'uploaded_at': data.get('uploaded_at', ''),
                })
            except Exception:
                pass

    return jsonify({
        'health': health,
        'total_identities': len(identities),
        'white_count': health['white_count'],
        'black_count': health['black_count'],
        'blocked_count': health['blocked_count'],
        'model_exists': model_exists(),
        'model': get_model_info(),
        'recent_analyses': analyses,
    })


# ═════════════════════════════════════════════════════════════════════════
#  API: DEEP FORENSIC ANALYSIS
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/analysis/<analysis_id>', methods=['GET'])
def get_analysis_details(analysis_id):
    """Return the detailed JSON report for Deep Forensic Analysis."""
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
        
    analysis_file = os.path.join(ANALYSIS_FOLDER, f"{analysis_id}.json")
    if not os.path.exists(analysis_file):
        return jsonify({'error': 'Analysis not found'}), 404
        
    with open(analysis_file, 'r') as fh:
        data = json.load(fh)
        
    return jsonify(data)

    
@app.route('/api/forensics/<analysis_id>', methods=['GET'])
def get_forensic_insights(analysis_id):
    """
    Return forensic insight data for the RecordsTable panel.
    Includes: top features, XAI insights, suggestions, and prediction summary.
    """
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400

    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404

    predictions = record.get('predictions', [])
    explanations = ensure_explanations(record)
    metadata = record.get('metadata', {})
    suggestions = build_analysis_suggestions(predictions)
    otx_summary = record.get('otx_summary') or summarize_otx_enrichment(predictions)

    return jsonify({
        'analysis_id': analysis_id,
        'filename': record.get('filename', 'unknown'),
        'status': record.get('status', 'unknown'),
        'source': record.get('source', 'upload'),
        'uploaded_at': record.get('uploaded_at', ''),
        'analyzed_at': record.get('analyzed_at', ''),
        'total_flows': len(predictions),
        'identities_created': len(set(record.get('identities_created', []))),
        'metadata': metadata,
        'predictions': predictions,
        'explanations': explanations,
        'otx_summary': otx_summary,
        'suggestions': suggestions,
    })



# ═════════════════════════════════════════════════════════════════════════
#  API: PDF REPORT
# ═════════════════════════════════════════════════════════════════════════

@app.route('/api/report/<analysis_id>', methods=['GET'])
def generate_report(analysis_id):
    """Generate and download a PDF forensic report."""
    if not _valid_analysis_id(analysis_id):
        return jsonify({'error': 'Invalid analysis ID'}), 400
    record = get_analysis(analysis_id)
    if not record:
        return jsonify({'error': 'Analysis not found'}), 404

    try:
        try:
            from reports.pdf_report import generate_pdf_report
        except ImportError:
            return jsonify({'error': 'PDF generation not available. Install reportlab: pip install reportlab'}), 500

        os.makedirs(REPORTS_FOLDER, exist_ok=True)
        explanations = ensure_explanations(record)
        report_metadata = dict(record.get('metadata', {}))
        report_metadata['otx_summary'] = record.get('otx_summary') or summarize_otx_enrichment(record.get('predictions', []))

        report_path = generate_pdf_report(
            analysis_id=analysis_id,
            analysis_data=record.get('flow_analysis', {}),
            predictions=record.get('predictions', []),
            explanations=explanations,
            topology={},
            metadata=report_metadata,
        )

        if not report_path or not os.path.exists(report_path):
            return jsonify({'error': 'Failed to generate report file'}), 500

        report_path = os.path.abspath(report_path)

        return send_file(
            report_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'ObsidianLens_Report_{analysis_id}.pdf',
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/batch', methods=['GET'])
def generate_batch_report():
    import zipfile
    import io
    from reports.pdf_report import generate_pdf_report
    
    ids_str = request.args.get('ids', '')
    fmt = request.args.get('format', 'zip')
    
    if not ids_str:
        return jsonify({'error': 'No ids provided'}), 400
        
    analysis_ids = ids_str.split(',')
    
    if fmt == 'pdf':
        # Generate a single cumulative report for all ids
        combined_predictions = []
        combined_explanations = []
        total_packets = 0
        total_identities = set()
        combined_protocols = {}
        top_flows = []
        
        for aid in analysis_ids:
            record = get_analysis(aid)
            if not record: continue
            
            combined_predictions.extend(record.get('predictions', []))
            
            # Take explanations from the first record that has them, as they characterize the model
            if not combined_explanations and record.get('explanations'):
                combined_explanations = record.get('explanations')
            
            metadata = record.get('metadata', {})
            total_packets += metadata.get('total_packets', 0)
            if 'identities_created' in record:
                total_identities.update(record['identities_created'])
                
            ana_data = record.get('flow_analysis', {})
            if 'protocol_distribution' in ana_data:
                for p in ana_data['protocol_distribution']:
                    proto = p['protocol']
                    if proto not in combined_protocols:
                        combined_protocols[proto] = {'packets': 0, 'bytes': 0}
                    combined_protocols[proto]['packets'] += p['packet_count']
                    combined_protocols[proto]['bytes'] += p['byte_count']
            
            if 'flow_summaries' in ana_data:
                top_flows.extend(ana_data['flow_summaries'])

        if not combined_predictions and not top_flows:
            return jsonify({'error': 'Failed to generate combined batch report (No data found)'}), 500

        total_packets_protos = sum(p['packets'] for p in combined_protocols.values())
        total_bytes_protos = sum(p['bytes'] for p in combined_protocols.values())
        agg_protocol_dist = []
        for proto, stats in combined_protocols.items():
            agg_protocol_dist.append({
                'protocol': proto,
                'packet_count': stats['packets'],
                'byte_count': stats['bytes'],
                'packet_ratio': stats['packets'] / total_packets_protos if total_packets_protos else 0,
                'byte_ratio': stats['bytes'] / total_bytes_protos if total_bytes_protos else 0,
            })
        agg_protocol_dist.sort(key=lambda x: x['byte_count'], reverse=True)
        top_flows.sort(key=lambda x: x['total_bytes'], reverse=True)
        
        combined_metadata = {
            'source': f'Cumulative Report ({len(analysis_ids)} Captures)',
            'total_packets': total_packets,
            'identities_created': len(total_identities),
            'otx_summary': summarize_otx_enrichment(combined_predictions),
        }
        
        combined_analysis_data = {
            'protocol_distribution': agg_protocol_dist,
            'flow_summaries': top_flows[:50]
        }
        
        path = generate_pdf_report(
            analysis_id="CUMULATIVE_BATCH",
            analysis_data=combined_analysis_data,
            predictions=combined_predictions,
            explanations=combined_explanations,
            topology={},
            metadata=combined_metadata,
        )
        
        if path and os.path.exists(path):
            return send_file(path, mimetype='application/pdf', as_attachment=True, download_name='ObsidianLens_Cumulative_Report.pdf')
        else:
            return jsonify({'error': 'Failed to generate cumulative batch report'}), 500
            
    else: # format == 'zip'
        pdf_paths = []
        for aid in analysis_ids:
            record = get_analysis(aid)
            if not record: continue
            
            path = generate_pdf_report(
                analysis_id=aid,
                analysis_data=record.get('flow_analysis', {}),
                predictions=record.get('predictions', []),
                explanations=record.get('explanations', []),
                topology={},
                metadata=record.get('metadata', {}),
            )
            if path and os.path.exists(path):
                pdf_paths.append((aid, path))

        if not pdf_paths:
            return jsonify({'error': 'Failed to generate any reports'}), 500
            
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for aid, path in pdf_paths:
                zf.write(path, arcname=f"Report_{aid}.pdf")
        memory_file.seek(0)
        
        return send_file(memory_file, mimetype='application/zip', as_attachment=True, download_name='ObsidianLens_Reports_Archive.zip')


@app.route('/api/analysis/clear_all_records', methods=['DELETE'])
def clear_all_records():
    """Clear all analysis records from the cache."""
    try:
        if os.path.exists(ANALYSIS_FOLDER):
            for file in os.listdir(ANALYSIS_FOLDER):
                if file.endswith('.json'):
                    try:
                        os.remove(os.path.join(ANALYSIS_FOLDER, file))
                    except:
                        pass
        return jsonify({'status': 'cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# ═════════════════════════════════════════════════════════════════════════
#  APP STARTUP & MLOps AUTO-INITIALIZATION
# ═════════════════════════════════════════════════════════════════════════

def auto_initialize_system():
    """Silently ensure the model and dataset exist on startup, and check dependencies."""
    # Pre-Flight OS Dependency Check
    import platform
    if platform.system() == "Windows":
        try:
            from scapy.all import conf
            if not getattr(conf, 'use_pcap', False):
                print("\n" + "!"*60)
                print("[CRITICAL WARNING] Npcap capture driver is not installed!")
                print("Live Packet Capture will SILENTLY FAIL in production.")
                print("Please download and install Npcap from: https://npcap.com/#download")
                print("!"*60 + "\n")
        except ImportError:
            print("\n[CRITICAL WARNING] Scapy is not installed. Networking functions will fail.\n")

    from ml.model_manager import model_exists
    
    if not model_exists():
        print("[*] No model detected. Training on real-world CICIDS2017 dataset...")
        try:
            import pandas as pd
            from ml.real_dataset_loader import load_real_dataset
            from ml.preprocessor import Preprocessor
            from ml.classifier import BehavioralClassifier
            from ml.model_manager import save_model

            print("  [->] Loading real-world dataset (this may take ~30s for large files)...")
            df = load_real_dataset(max_rows=100000)

            # Merge RL feedback if it exists
            rl_path = os.path.join(BASE_DIR, 'data', 'rl_feedback.csv')
            if os.path.exists(rl_path):
                rl_df = pd.read_csv(rl_path)
                df = pd.concat([df, rl_df], ignore_index=True)
                print(f"  [->] Merged {len(rl_df)} RL feedback rows.")

            print("  [->] Training Weighted Random Forest on real traffic patterns...")
            preprocessor = Preprocessor()
            X, y = preprocessor.fit_transform(df)

            classifier = BehavioralClassifier()
            metrics = classifier.train(X, y)
            save_model(classifier, preprocessor, metadata=metrics)
            print(f"[✓] Model trained. Accuracy: {metrics.get('cv_mean_accuracy', 'N/A')}")
            print("[✓] System ready to detect DDoS, botnet, and anomalous traffic.")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[!] Error during startup training: {e}")

# ═════════════════════════════════════════════════════════════════════════
#  RUN
# ═════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("\n" + "!" * 80)
            print(" [CRITICAL ERROR] ADMINISTRATOR PRIVILEGES REQUIRED ")
            print("!" * 80)
            print(" The Obsidian Lens MUST be run as an Administrator.")
            print(" Both Live Packet Capture (Npcap) and Identity Firewall Blocking (netsh)")
            print(" will fail essentially silently without high-level execution rights.")
            print("\n Action Required: Restart your terminal/IDE as Administrator,")
            print(" then run 'python app.py' again.")
            print("!" * 80 + "\n")
            import sys
            sys.exit(1)

    print("\n" + "=" * 60)
    print("   THE OBSIDIAN LENS — Network Forensic Tool")
    print("   49-Parameter Behavioral Analysis | Identity Tracking")
    print("   Server running at http://localhost:5000")
    print("=" * 60 + "\n")
    auto_initialize_system()
    app.run(debug=False, host='0.0.0.0', port=5000)
