# BankSentinel AI — Project Context & Implementation History
**Date:** July 2026

This document serves as a comprehensive, highly detailed ledger of every architectural change, script creation, and analysis step performed during this session for the **BankSentinel AI** project.

---

## 1. Initial Analysis: Identifying "GIBL" & The Codebase
The initial task was to explore the repository to understand the core context of the project.
- **Discovery**: The `GIBL` folder and acronym explicitly refer to **Global IME Bank Limited**, a leading Class 'A' commercial bank in Nepal.
- **System Purpose**: **BankSentinel** is a Five-Agent AI-Driven Intrusion Detection System (IDS). It is explicitly engineered for Nepalese financial networks, handling specific traffic regimes (e.g., ATM reconciliation, RTGS settlement hours), and automatically generates compliance reports mapped directly to the **Nepal Rastra Bank (NRB) Cyber Security Framework**.
- **Agent Architecture**:
  1. **Packet Agent**: Encrypted TLS 1.3 C2 beacon detection (JA3/JA3S).
  2. **Flow Agent**: Bulk network flow analysis using Isolation Forests mapped to Nepal banking hours.
  3. **Behavior Agent**: Zero-day insider threat detection using a BiLSTM Autoencoder on user event sequences.
  4. **Correlation Agent**: The Bayesian "brain" that fuses alerts and suppresses false positives.
  5. **Response Agent**: Automated, millisecond-speed network containment with cryptographic auditing.

---

## 2. Packet Agent Dataset Management
The user provided a raw, custom Zeek connection log dataset formatted for the Packet Agent. 

**The Dataset Format:**
`log_id, ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, missed_bytes, orig_pkts, resp_pkts, tunnel_parents, is_anomaly, anomaly_type, ja3_hash, ja3s_hash`

**What Was Changed:**
- **Created `clean_packet.py`**: A standalone preprocessing script was written to ingest this raw Zeek CSV. 
  - **Handling Zeek Nuances**: Zeek logs frequently represent missing or incomplete data (like duration on dropped connections) with a literal `-` string. The script finds all instances of `-` and empty strings and explicitly maps them to `NaN`.
  - **Numeric Type Enforcement**: It forces critical beacon timing columns (`duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`) into floating-point numbers.
  - **Label Standardization**: The `is_anomaly` column is mapped into a strict boolean format to ensure `train_packet.py` can calculate class distributions correctly.
  - **Filtering**: Drops any rows entirely missing critical connection identifiers (like protocol or destination port).
  - This script bridges the gap between raw network capture and the Random Forest expected by `train_packet.py`.

---

## 3. Behavior Agent Concept Clarification
We engaged in a deep dive into how the zero-day Behavior Agent works.
- **The Core Mechanism**: The Behavior Agent utilizes a **Bidirectional LSTM Autoencoder**. It is an unsupervised anomaly detection model.
- **The Paradigm Shift**: Unlike signature-based scanners (like Snort), the Behavior Agent **never looks at attacks during training**. It is exclusively trained on ~30 days of **normal** user sequences (e.g., standard employee login hours, normal database query volumes). 
- **Detection via Deviation**: During live inference, it attempts to reconstruct the input sequence. If a user acts maliciously (a zero-day attack), the sequence deviates from the learned normal, causing the **mean squared reconstruction error** to spike above a calculated 95th-percentile threshold.
- **No Attack Data Needed**: This confirmed that to deploy the agent, the bank only needs to supply baseline normal data. It does not require continuous retraining every time a new attack is discovered in the wild.

---

## 4. Dual-Dataset Behavior Agent Overhaul (The Major Refactor)
The user introduced a major architectural change: The Behavior Agent must now ingest, fuse, and evaluate signals from **two completely distinct datasets** simultaneously to make a unified decision.

**Dataset 1: User Behavior Events**
`event_id, timestamp, username, hostname, event_type, resource_accessed, bytes_transferred, duration_sec, source_ip, is_off_hours, is_new_resource, failed_attempts_prior_1h, peer_group_deviation_score, is_anomaly, anomaly_type, mitre_technique`

**Dataset 2: Windows Event Logs**
`event_id, event_log_id, timestamp, hostname, domain, event_name, event_description, subject_username, subject_domain, target_username, target_domain, logon_type, logon_type_name, process_name, process_id, parent_process, source_ip, workstation_name, failure_reason, is_anomaly, anomaly_type, mitre_technique`

To achieve this, almost the entire Behavior Agent pipeline was rewritten.

### What Was Changed in Detail:

#### A. Data Standardization Pipeline (`Cleaned_behaviour.py`)
- **Created a new script `Cleaned_behaviour.py`** to ingest the two raw datasets and produce two standardized CSV files (`cleaned_dataset_1.csv` and `cleaned_dataset_2.csv`).
- **Column Unification**: Mapped divergent column names (e.g., mapping `subject_username` in Dataset 2 to `username` to match Dataset 1).
- **Missing Value Defaulting**: It explicitly fills missing features with defaults (e.g., `0.0` for bytes transferred, `-1` for unknown logon types).
- **Dataset Source Tagging**: A new column `dataset_source` was injected (`1` for User Behavior, `2` for Windows Events) so the downstream model knows where the event originated.

#### B. Configuration Update (`config.py`)
- **Modified `BEHAVIOR_INPUT_SIZE`**: The input dimensionality of the BiLSTM was bumped from **8 dimensions** to **14 dimensions** to accommodate the unified feature space.

#### C. Training Engine Overhaul (`train_behavior.py`)
- **Completely Rewrote the Script**: The previous script loaded a pre-packaged pickle file. The new script is vastly more complex.
- **Chronological Fusion**: It accepts both cleaned CSVs, concatenates them into a single massive dataframe, and **sorts everything chronologically by `username` and `timestamp`**. This ensures the BiLSTM sees a seamless, interleaved timeline of a user's actions across both datasets.
- **14-Dimensional Feature Engineering**: For every single event across both datasets, it calculates a 14-dimensional vector:
  1. `dataset_source` (Float indicator)
  2. `hour_sin` (Cyclic time feature)
  3. `hour_cos` (Cyclic time feature)
  4. `event_id_norm` (MD5 hashed to a [0, 1] float)
  5. `ds1_bytes_transferred_log` (Log-scaled)
  6. `ds1_duration_sec`
  7. `ds1_is_off_hours`
  8. `ds1_is_new_resource`
  9. `ds1_failed_attempts`
  10. `ds1_peer_deviation`
  11. `ds2_logon_type_norm`
  12. `is_sensitive_target` (Regex search on target processes/usernames for 'admin' or 'system')
  13. `ip_cluster` (MD5 hashed source IP)
  14. `query_rate` (A dynamically computed rolling 5-minute count of total actions across BOTH datasets for that specific user)
- **Sequence Generation**: It slices the user timelines into non-overlapping sequential chunks of `BEHAVIOR_SEQUENCE_LENGTH` (20 events). 
- **Train/Test Splitting**: Any sequence containing even a single anomalous event (`is_anomaly == True`) is isolated. The normal sequences are used to train the BiLSTM Autoencoder, and the anomalous sequences are saved to `models/behavior_test_attacks.pkl` for testing.

#### D. Inference Pipeline & Model Updates (`agents/behaviour_agent.py`)
- **Modified `BehaviorDataGenerator`**: Updated the synthetic data generator used for hackathon smoke tests. `DIM_NAMES` was expanded from 8 to 14. The `normal_sequence()` and the 5 attack scenario generators (`credential_abuse_sequence`, `lateral_movement_sequence`, etc.) were rewritten to populate the 14-dimensional array, guaranteeing the smoke tests will not crash with a shape mismatch error.
- **Modified `_record_to_sequence`**: Updated the inference mapping logic so that when the agent processes a live `FlowRecord` from the network, it maps the real-time features into the new 14-index positions (e.g., moving `query_rate` to index 13 and `peer_z_score` to index 9).
- **Modified `_identify_scenario`**: Updated the heuristic scenario tagging (which determines if an anomaly is a "Privilege Escalation" vs "Insider Exfiltration") to point to the new array indices for privileges, query rates, and IP variance.

---

### Summary of System State
The BankSentinel codebase is currently sitting in a fully operational state under the new dual-dataset architecture. The models expect 14-dimensional sequences. The cleaning, training, and inference pipelines are fully aligned end-to-end to ingest real data, fuse it chronologically by user, and detect zero-day deviations.

---

## 5. Packet Agent Dynamic Thresholding & Class Imbalance
The Packet Agent was exhibiting a hard 59% detection rate cap on the validation set. Two significant architectural changes were made to resolve model accuracy and thresholding rigidity.

#### A. Class Imbalance Fix (`train_packet.py`)
- **Diagnosis**: The Random Forest was capping at 59% recall because the benign class overwhelmingly outnumbered the attack class in the CTU-13 dataset, causing the decision trees to prioritize overall accuracy at the expense of minority class recall.
- **Fix**: Implemented `class_weight='balanced_subsample'` in the `RandomForestClassifier` instantiation to mathematically penalize false negatives on the minority attack class.

#### B. Dynamic Thresholding (`calibrate_l3_threshold.py` & `packet_agent.py`)
- **Diagnosis**: The Packet Agent relied on a static configuration variable `BEACON_IAT_CV_THRESHOLD = 0.30`. This made the agent rigid and incapable of adapting to different network baseline noise levels.
- **Fix**: Converted the Packet Agent to load a dynamically computed threshold (`packet_threshold.pkl`) at runtime.
- **Calibration Update**: Rewrote `calibrate_l3_threshold.py`. It previously generated synthetic dummy data (causing broken thresholds like `0.1400` that destroyed detection rates). It was rewritten to ingest a real target CSV, extract the exact Random Forest probability cutoff required to hit a specific Target False Positive Rate (e.g., `--target-fpr 0.05`), and serialize the result to `packet_threshold.pkl`.

---

## 6. Live Production Mode: Simulators Removed & Suricata Exposed
The backend API (`api/main.py` and `api/routes/pipeline.py`) contained several synthetic data generators used for demonstrations. These were entirely ripped out to prepare for live deployment.

#### A. Simulator Purge
- Deleted the background traffic generator `api/simulator.py`.
- Removed `start_simulator()` and `stop_simulator()` hooks from the FastAPI lifespan events in `main.py`.
- Deleted the `/pipeline/mode` endpoints since "simulated" mode no longer exists.

#### B. Demo Scenarios Removed
- Deleted the `/pipeline/apt-demo` endpoint.
- Removed the hardcoded Cobalt Strike `JA3` hash injection that was artificially poisoning the Threat Intel engine database. The Threat Intel engine is now strictly driven by live, unmodified `abuse.ch` intelligence.

#### C. Suricata Endpoint
- The system is now fully prepared to accept live Suricata EVE JSON streams via `POST http://<SERVER_IP>:8000/pipeline/suricata`. Since the app binds to `0.0.0.0`, the port is inherently open to the local network for external laptop ingestion.

---

## 7. Flow Agent Evaluation (agents/Flow Agent — Track D Model)
**Date:** July 3, 2026

A deep evaluation was performed on the standalone **Flow Agent** in `agents/Flow Agent/`. This is the **Track D competition model** — a separate, fully self-contained implementation from the six-regime `agents/flow_agent.py` described in the research paper. It uses a **hybrid XGBoost + Isolation Forest** blended pipeline.

### A. Architecture
- **Training** (`training.py`): 5-fold stratified CV XGBoost + multi-seed IF on temporal splits of `data/netflow_records.csv`. Bundle serialized to `models/*.pkl`.
- **Inference** (`inference.py`): `predict_final()` blends XGBoost + IF scores using tuned `alpha`, applies honeypot business-rule overrides, returns `(scores, criticalities)` tuple.
- **Feature engineering** (`flow_utils.py`): 18 numeric, 9 categorical (freq-encoded), 5 boolean features. Two stateful rolling-window features (`flows_per_src_5min`, `swift_query_2min`) are computed at batch time and defaulted to `1` during single-row inference.
- **Suricata bridge** (`suricata_to_inference.py`): Parses Suricata EVE JSON and maps flow events to the agent schema.

### B. Model Performance (Stored Metrics — v2_track_d_20260703_182711.pkl)
| Split | AUROC | Precision | Recall | F1 |
|-------|-------|-----------|--------|----|
| Validation | 0.99999 | 0.9991 | 1.0000 | 0.9996 |
| **Test** | **1.0000** | **1.0000** | **1.0000** | **1.0000** |

- **Isolation Forest Val AUROC (3-seed mean):** 0.9987 ± 0.0003
- **Threshold (F1-optimal):** 0.91 | **XGBoost Inference Latency:** 10.3ms mean, 14.2ms p95
- **Critical finding:** `blend.alpha = 1.0` — the IF score contributes **0%** to the final decision. All detection is currently supervised-only. Zero-day/unsupervised detection is disabled in production.

### C. Test Suite Bugs Found and Fixed
Two bugs in `test_flow_agent.py` were identified and patched:
1. **Stale import:** `from inference_flow_agent import predict_final` — module was renamed to `inference.py`. Fixed to `from inference import predict_final`.
2. **API mismatch:** All 4 test functions called `scores = predict_final(...)` but the function now returns a `(scores, criticalities)` tuple. Fixed to `scores, _ = predict_final(...)`.
- **Result after fixes:** 4/4 original tests + 8/8 extended tests = **12/12 total PASS**.

### D. Suricata Live-Data Evaluation (39,682 flows)
- **Alerts triggered:** 216 (0.54% of flows) — all tagged `ELEVATED_SEVERITY` (no host profiles loaded)
- **Top pattern:** `172.19.101.91 -> 172.19.101.27` on port `1716` with score `1.0000` — high-confidence lateral movement candidate.
- **Score distribution:** Bimodal — 99th percentile is 0.796, then a sharp jump to 1.0 for alerts. Indicates poor calibration in the mid-range (0.80-0.91 gap is effectively a dead zone).

### E. Key Recommendations (Priority Order)
1. **Re-tune blend alpha <= 0.8** to restore zero-day detection capability from the Isolation Forest.
2. **Fix XGBoost device warning** (`cuda:0` vs CPU input) — align input device to avoid latency-penalizing CPU-to-GPU copies.
3. **Apply score calibration** (Platt scaling or isotonic regression) to fix the bimodal score distribution.
4. **Populate `host_profiles.csv`** to enable `CRITICAL_SEVERITY` and `HIGH_SEVERITY` alert tiers for SWIFT/ATM hosts.
5. **Fix Suricata field mapping:** `tcp_flags` arrives as hex strings (e.g., `0x18`) vs. trained flag categories (`PA`, `S`); `segment` always defaults to `USER` instead of VLAN-derived values.
6. **Fix stale import in `cross_reference_alerts.py` line 6** — same `inference_flow_agent` module name bug as in the test file.

---

## 8. Codebase Reorganization and Optimization
**Date:** July 3, 2026

A comprehensive restructuring of the GIBL repository was executed to resolve clutter and establish clean architecture.

### A. Subdirectory Restructuring
- **pipeline/data_preparation/**: Consolidated packet, behavior, and netflow preprocessing/cleaning scripts here.
- **scripts/**: Grouped utility, threshold calibration, and helper scripts here.
- **training/**: Centralized model training scripts (, , ).
- **demo/**: Relocated attack simulation and example inference runs.
- **tests/**: Unified all unit tests into a single directory. Moved Track D test and other helpers out of agent/root paths.

### B. Code & Test Compatibility Fixes
- **pgmpy DiscreteBayesianNetwork integration**: Updated BBN inference engine in `agents/correlation_agent.py` to use `DiscreteBayesianNetwork` instead of the deprecated `BayesianNetwork` class to solve `ImportError`-induced manual Bayes fallbacks.
- **CRS dynamic weight assertions**: Updated `tests/test_correlation_agent.py` to compute expected CRS value matching the dynamic confidence-weighting formulation instead of static weights.
- **Flow Agent threshold assertions**: Patched flat-dict regime checks in `tests/test_flow_agent.py`.

### C. Convenient Start Scripts
- Created `run_frontend.sh` and `run_backend.sh` in the root directory. Made them executable for quick startup.

### D. Verification Results
- Ran `pytest tests/` with all **243/243 tests successfully passing**.
- Verified backend starts and successfully loads all 5 ML agents, including exact BBN inference via pgmpy.

---

## 9. Model Verification & Agent 4 Data Preparation
**Date:** July 3, 2026

An evaluation script path fix, a centralized model checking suite, and an Agent 4 data preprocessing pipeline were successfully implemented.

### A. Evaluation Scripts Path Fixes
- Relocated `evaluate_test_csv.py` and `evaluate_test_packet_csv.py` from the root folder to `scripts/`.
- Fixed their path setups (`sys.path.insert(0, ...)`) and updated imports to target `training.train_behavior` and `training.train_packet` respectively, resolving all `ModuleNotFoundError` crashes.

### B. Centralized Model Test Script
- Created `tests/test_all_models_working.py` to programmatically load and exercise all four trained ML models (Packet, Behavior, Paper Flow, and Track D Flow) using dummy inputs. Verification executed and successfully passed.

### C. Agent 4 Data Preprocessing Script
- Created `pipeline/data_preparation/cleaned_for_agent4.py` to merge Alerts and Tickets and generate temporal 80-20 splits (`cleaned_agent4_train.csv` and `cleaned_agent4_test.csv`).
- **Data Leakage Guards**: Dropped 13 identifier and outcome-linked leakage columns (`fp_reason`, `containment_action`, `resolution_notes`, `status`, `analyst_assigned`, `financial_impact_npr`, `is_confirmed_attack`, `updated_at`, `alert_id`, `ticket_id`, `correlated_flow_id`, `initial_alert_id`, `mitre_navigator_link`).
- **Temporal Splitting**: Chronological sort by timestamp before split, converting timestamp into cyclic hour and day-of-week feature integers.

### D. Verification Results
- All unit tests passed, including the new model verification test file.
- Launched the backend API; verified successful agent registry loading (all 5 agents verified working under exact pgmpy BBN inference) and integration checks.

---

## 10. Agent 4 Model Training implementation
**Date:** July 3, 2026

An XGBoost classifier training script for the Correlation Agent (Agent 4) was successfully implemented.

### A. Overfitting Guard Implementation
- Created `training/train_correlation.py` with strict controls (Option 2: Max Depth Control).
- Model architecture utilizes a small default `max_depth=3` (or 4), low learning rate (`0.05`), L2 regularization (`reg_lambda=3.0`), and column/row subsampling.
- Implements class imbalance scaling via dynamic `scale_pos_weight` computation and triggers early stopping at 20 rounds of stagnation.


- **Dtype Mapping Bug Fixed**: Updated categorical detection to use pandas `is_numeric_dtype` and `is_bool_dtype` APIs. This handles all string, object, and mixed types robustly, preventing XGBoost ValueError crashes.

### B. Usage Instructions
- The script has been made executable and is ready to be run on private datasets:
  `python training/train_correlation.py --train <train_split.csv> --test <test_split.csv> --output-model models/correlation_classifier.pkl`
