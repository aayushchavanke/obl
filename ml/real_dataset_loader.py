"""
BENFET ML - Real-World Dataset Loader
Loads and maps the CICIDS2017 dataset columns to BENFET's 78 FEATURE_COLUMNS.

The CICIDS dataset uses human-readable column names with spaces and mixed case.
This module provides column mapping and a clean loading pipeline.

Dataset: CIC-IDS-2017 (Canadian Institute for Cybersecurity)
Labels in DDoS file: BENIGN, DDoS
"""

import os
import numpy as np
import pandas as pd
from config import BASE_DIR
from ml.labels import AttackType

PRIMARY_DATASET_DIR = os.path.join(BASE_DIR, 'datasets', 'real_world')
FALLBACK_DATASET_DIR = os.path.join(BASE_DIR, 'datasets')


def _resolve_dataset_dir():
    for candidate in (PRIMARY_DATASET_DIR, FALLBACK_DATASET_DIR):
        if not os.path.isdir(candidate):
            continue
        if any(name.lower().endswith('.csv') for name in os.listdir(candidate)):
            return candidate
    return PRIMARY_DATASET_DIR

# ─── Column Mapping: CICIDS Column → BENFET FEATURE_COLUMN ───────────────────
# Maps the raw CICIDS2017 header names (stripped) to our internal snake_case names.

CICIDS_COLUMN_MAP = {
    'Flow Duration':           'flow_duration',

    # Overall IAT
    'Flow IAT Mean':           'iat_mean',
    'Flow IAT Std':            'iat_std',
    'Flow IAT Min':            'iat_min',
    'Flow IAT Max':            'iat_max',

    # Forward IAT
    'Fwd IAT Mean':            'fwd_iat_mean',
    'Fwd IAT Std':             'fwd_iat_std',
    'Fwd IAT Min':             'fwd_iat_min',
    'Fwd IAT Max':             'fwd_iat_max',

    # Backward IAT
    'Bwd IAT Mean':            'bwd_iat_mean',
    'Bwd IAT Std':             'bwd_iat_std',
    'Bwd IAT Min':             'bwd_iat_min',
    'Bwd IAT Max':             'bwd_iat_max',

    # Active / Idle times
    'Active Mean':             'active_time_mean',
    'Active Std':              'active_time_std',
    'Active Min':              'active_time_min',
    'Active Max':              'active_time_max',
    'Idle Mean':               'idle_time_mean',
    'Idle Std':                'idle_time_std',
    'Idle Min':                'idle_time_min',
    'Idle Max':                'idle_time_max',

    # Spatial — directional packet counts
    'Total Fwd Packets':       'total_fwd_packets',
    'Total Backward Packets':  'total_bwd_packets',

    # Spatial — directional byte counts (not directly in CICIDS as separate cols — use segment sizes * packet count)
    'Subflow Fwd Bytes':       'total_fwd_bytes',
    'Subflow Bwd Bytes':       'total_bwd_bytes',

    # Forward packet length stats
    'Fwd Packet Length Mean':  'fwd_pkt_len_mean',
    'Fwd Packet Length Std':   'fwd_pkt_len_std',
    'Fwd Packet Length Min':   'fwd_pkt_len_min',
    'Fwd Packet Length Max':   'fwd_pkt_len_max',

    # Backward packet length stats
    'Bwd Packet Length Mean':  'bwd_pkt_len_mean',
    'Bwd Packet Length Std':   'bwd_pkt_len_std',
    'Bwd Packet Length Min':   'bwd_pkt_len_min',
    'Bwd Packet Length Max':   'bwd_pkt_len_max',

    # Overall packet size
    'Average Packet Size':     'avg_packet_size',
    'Packet Length Variance':  'pkt_len_variance',

    # Volumetric
    'Flow Bytes/s':            'flow_bytes_per_sec',
    'Flow Packets/s':          'flow_packets_per_sec',
    'Down/Up Ratio':           'down_up_ratio',

    # TCP/IP
    'Init_Win_bytes_forward':  'init_win_fwd',
    'Init_Win_bytes_backward': 'init_win_bwd',
    'Fwd Header Length':       'fwd_header_len',
    'Bwd Header Length':       'bwd_header_len',
    'FIN Flag Count':          'fin_flag_count',
    'SYN Flag Count':          'syn_flag_count',
    'RST Flag Count':          'rst_flag_count',
    'PSH Flag Count':          'psh_flag_count',
    'ACK Flag Count':          'ack_flag_count',
    'URG Flag Count':          'urg_flag_count',

    # Label
    'Label':                   'label',
}

# ─── Label Mapping: CICIDS label → internal BENFET profile label ─────────────
LABEL_MAP = {
    'BENIGN':   AttackType.WEB_BROWSER.value,
    'DDoS':     AttackType.DDOS.value,
    'DoS Hulk': AttackType.DDOS.value,
    'DoS GoldenEye': AttackType.DDOS.value,
    'DoS slowloris': AttackType.DDOS.value,
    'DoS Slowhttptest': AttackType.DDOS.value,
    'PortScan':  AttackType.PORT_SCAN.value,
    'Bot':       AttackType.BOTNET.value,
    'Infiltration': AttackType.APT_EXFILTRATION.value,
    'Web Attack – Brute Force': AttackType.BRUTE_FORCE_SSH.value,
    'Web Attack – XSS': AttackType.BRUTE_FORCE_SSH.value,
    'Web Attack – Sql Injection': AttackType.BRUTE_FORCE_SSH.value,
    'FTP-Patator': AttackType.BRUTE_FORCE_SSH.value,
    'SSH-Patator': AttackType.BRUTE_FORCE_SSH.value,
    'Heartbleed': AttackType.MALWARE_C2.value,
}


def load_real_dataset(max_rows=None, label_map=None):
    """
    Load all CSV files from the real_world dataset folder, map columns to
    BENFET FEATURE_COLUMNS format, clean data, and return a training-ready DataFrame.

    Args:
        max_rows: Cap total rows (None = load all). Recommended: 100000 for fast training.
        label_map: Override the default LABEL_MAP.

    Returns:
        pd.DataFrame with exactly FEATURE_COLUMNS + 'label' columns.
    """
    from ml.preprocessor import FEATURE_COLUMNS

    if label_map is None:
        label_map = LABEL_MAP

    dataset_dir = _resolve_dataset_dir()

    csv_files = [
        os.path.join(dataset_dir, f)
        for f in os.listdir(dataset_dir)
        if f.endswith('.csv')
    ]

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {dataset_dir}.\n"
            "Please add CICIDS2017 CSV files to datasets/ or datasets/real_world/"
        )

    print(f"[DATASET] Found {len(csv_files)} CSV files in {dataset_dir}")

    all_frames = []
    for csv_path in csv_files:
        print(f"  -> Loading: {os.path.basename(csv_path)}")
        df = pd.read_csv(csv_path, low_memory=False)

        # Strip whitespace from all column names
        df.columns = [c.strip() for c in df.columns]

        # Apply column mapping
        rename_map = {k: v for k, v in CICIDS_COLUMN_MAP.items() if k in df.columns}
        df = df.rename(columns=rename_map)

        all_frames.append(df)

    combined = pd.concat(all_frames, ignore_index=True)
    print(f"[DATASET] Raw combined shape: {combined.shape}")

    # Map labels
    if 'label' not in combined.columns and 'Label' in combined.columns:
        combined = combined.rename(columns={'Label': 'label'})

    combined['label'] = combined['label'].str.strip()
    combined['label'] = combined['label'].map(label_map).fillna(AttackType.WEB_BROWSER.value)

    print(f"[DATASET] Label distribution:\n{combined['label'].value_counts().to_dict()}")

    # fwd_bwd_packet_ratio — derivable from CICIDS data
    if 'fwd_bwd_packet_ratio' not in combined.columns:
        combined['fwd_bwd_packet_ratio'] = (
            combined['total_fwd_packets'] / combined['total_bwd_packets'].replace(0, 1)
        )

    # Keep only FEATURE_COLUMNS + label
    keep_cols = FEATURE_COLUMNS + ['label']
    combined = combined[[c for c in keep_cols if c in combined.columns]]

    # Ensure all FEATURE_COLUMNS are present (fill any remaining gaps with 0)
    for col in FEATURE_COLUMNS:
        if col not in combined.columns:
            print(f"  [WARN] Feature '{col}' still missing after mapping — filling with 0")
            combined[col] = 0

    # Clean: replace inf/NaN with 0
    combined[FEATURE_COLUMNS] = combined[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    combined[FEATURE_COLUMNS] = combined[FEATURE_COLUMNS].fillna(0)

    # Convert all feature columns to float
    combined[FEATURE_COLUMNS] = combined[FEATURE_COLUMNS].astype(float)

    # Optional row cap
    if max_rows and len(combined) > max_rows:
        combined = combined.sample(n=max_rows, random_state=42).reset_index(drop=True)
        print(f"[DATASET] Sampled down to {max_rows} rows for training.")

    print(f"[DATASET] Final training shape: {combined.shape}")
    return combined
