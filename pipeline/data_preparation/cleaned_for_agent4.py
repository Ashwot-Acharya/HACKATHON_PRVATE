#!/usr/bin/env python3
"""
cleaned_for_agent4.py

Data preparation script for GIBL Correlation Agent (Agent 4).
Loads raw alerts and ticket files, performs temporal splitting (80/20) 
to prevent target leakage, and filters out post-incident and identifier columns.

Usage:
    python cleaned_for_agent4.py --alerts <path_to_alerts.csv> \
                                 --tickets <path_to_tickets.csv> \
                                 --output-dir <path_to_output_folder>
"""

import os
import sys
import argparse
import logging
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("gibl.data_prep_agent4")


def parse_args():
    parser = argparse.ArgumentParser(description="Clean and split GIBL Agent 4 alerts/tickets datasets.")
    parser.add_argument("--alerts", required=True, type=str, help="Path to raw alerts CSV file")
    parser.add_argument("--tickets", required=True, type=str, help="Path to raw tickets CSV file")
    parser.add_argument("--output-dir", required=True, type=str, help="Path to output directory")
    return parser.parse_args()


def prepare_agent4_datasets(alerts_path: str, tickets_path: str, output_dir: str):
    # 1. Validate paths
    if not os.path.exists(alerts_path):
        logger.error(f"Alerts file not found: {alerts_path}")
        sys.exit(1)
    if not os.path.exists(tickets_path):
        logger.error(f"Tickets file not found: {tickets_path}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    # 2. Load Datasets
    logger.info("Loading Alerts dataset...")
    alerts = pd.read_csv(alerts_path)
    logger.info(f"Loaded {len(alerts)} alerts. Columns: {list(alerts.columns)}")

    logger.info("Loading Tickets dataset...")
    tickets = pd.read_csv(tickets_path)
    logger.info(f"Loaded {len(tickets)} tickets. Columns: {list(tickets.columns)}")

    # 3. Handle Timestamps
    # Parse timestamps to avoid string comparisons and sort chronologically
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
    tickets["created_at"] = pd.to_datetime(tickets["created_at"], errors="coerce")

    # Drop rows without timestamps (unusable for chronological split)
    initial_alerts_len = len(alerts)
    alerts = alerts.dropna(subset=["timestamp"])
    if len(alerts) < initial_alerts_len:
        logger.warning(f"Dropped {initial_alerts_len - len(alerts)} alerts due to missing or invalid timestamps.")

    # 4. Perform Left Merge to chain alerts with ticket campaigns
    logger.info("Merging alerts and tickets on initial_alert_id...")
    # Tickets CSV has initial_alert_id, Alerts CSV has alert_id
    merged = pd.merge(
        alerts,
        tickets,
        left_on="alert_id",
        right_on="initial_alert_id",
        how="left",
        suffixes=("_alert", "_ticket")
    )
    logger.info(f"Merged dataset contains {len(merged)} records.")

    # 5. Define Target Label and apply confirmation logic
    # Set target is_true_positive. If alert is connected to a confirmed ticket, override as True.
    if "is_true_positive" not in merged.columns:
        # Fallback if target column is named differently
        logger.warning("Target column 'is_true_positive' not found in alerts dataset! Synthesizing from tickets...")
        merged["is_true_positive"] = False

    # Standardize boolean targets
    merged["is_true_positive"] = merged["is_true_positive"].fillna(False).astype(bool)
    if "is_confirmed_attack" in merged.columns:
        merged["is_confirmed_attack"] = merged["is_confirmed_attack"].fillna(False).astype(bool)
        # Any alert that belongs to a confirmed attack ticket is a true positive
        confirmed_mask = merged["is_confirmed_attack"] == True
        original_tp_count = merged["is_true_positive"].sum()
        merged.loc[confirmed_mask, "is_true_positive"] = True
        new_tp_count = merged["is_true_positive"].sum()
        logger.info(f"Updated True Positive count based on confirmed attacks: {original_tp_count} -> {new_tp_count}")

    # 6. Address Data Leakage
    # Drop post-incident outcome features (analyst notes, resolution states, etc.)
    # Drop identifiers that cause memorization / signature leakage.
    leakage_cols_to_drop = [
        # Post-Incident / Analyst Action Leakage Columns
        "fp_reason",
        "containment_action",
        "resolution_notes",
        "status",
        "analyst_assigned",
        "financial_impact_npr",
        "is_confirmed_attack",  # Directly leaks ticket status
        "updated_at",           # Outcome-linked timestamp
        
        # Identifier Leakage Columns
        "alert_id",
        "ticket_id",
        "correlated_flow_id",
        "initial_alert_id",
        "mitre_navigator_link"
    ]

    existing_leakage_cols = [col for col in leakage_cols_to_drop if col in merged.columns]
    logger.info(f"Dropping the following columns to prevent DATA LEAKAGE: {existing_leakage_cols}")
    cleaned = merged.drop(columns=existing_leakage_cols, errors="ignore")

    # 7. Chronological (Temporal) 80-20 Train-Test Split
    # Sorting by alert timestamp first to prevent time travel/temporal leakage
    cleaned = cleaned.sort_values(by="timestamp").reset_index(drop=True)
    
    split_idx = int(len(cleaned) * 0.8)
    train_df = cleaned.iloc[:split_idx].copy()
    test_df = cleaned.iloc[split_idx:].copy()

    # Drop timestamp from final training feature set if desired to prevent time-signature bias,
    # but we can also convert it to cyclic features (e.g. hour, day of week)
    if "timestamp" in train_df.columns:
        for df in [train_df, test_df]:
            df["hour"] = df["timestamp"].dt.hour
            df["day_of_week"] = df["timestamp"].dt.dayofweek
            # drop raw timestamp column
            df.drop(columns=["timestamp", "created_at"], errors="ignore", inplace=True)

    # 8. Report Split Distributions and Class Balances
    train_tp_rate = train_df["is_true_positive"].mean()
    test_tp_rate = test_df["is_true_positive"].mean()

    logger.info(f"Training set: {len(train_df)} rows, True Positive Rate: {train_tp_rate:.2%}")
    logger.info(f"Testing set: {len(test_df)} rows, True Positive Rate: {test_tp_rate:.2%}")

    # 9. Save Files
    train_output_path = os.path.join(output_dir, "cleaned_agent4_train.csv")
    test_output_path = os.path.join(output_dir, "cleaned_agent4_test.csv")

    train_df.to_csv(train_output_path, index=False)
    test_df.to_csv(test_output_path, index=False)

    logger.info(f"SUCCESS: Saved training set to {train_output_path}")
    logger.info(f"SUCCESS: Saved testing set to {test_output_path}")


if __name__ == "__main__":
    args = parse_args()
    prepare_agent4_datasets(args.alerts, args.tickets, args.output_dir)
