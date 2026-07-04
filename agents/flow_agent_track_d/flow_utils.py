import pandas as pd
import numpy as np

NUMERIC_COLS = [
    "duration_sec", "bytes_sent", "bytes_recv", "packets_sent", "packets_recv",
    "bytes_ratio", "pkt_ratio", "avg_bytes_per_pkt_sent", "avg_bytes_per_pkt_recv",
    "total_bytes", "total_packets", "hour_npt", "weekday", "day_of_month",
    "is_weekend", "is_month_end_window", "flows_per_src_5min", "swift_query_2min"
]

CATEGORICAL_COLS = [
    "protocol", "tcp_flags", "segment", "application_guess",
    "src_criticality", "dst_criticality", "src_host_type", "dst_host_type", "dst_port"
]

BOOL_COLS = [
    "is_internal_src", "is_internal_dst", "src_is_honeypot", "dst_is_honeypot", "is_syn_only",
]

ALL_FEATURE_COLS = NUMERIC_COLS + CATEGORICAL_COLS + BOOL_COLS

def rolling_count(df, group_col, window_minutes, mask=None):
    """Trailing window row-count per group. df.index must be a plain RangeIndex."""
    window = np.timedelta64(window_minutes, "m")
    counts = np.zeros(len(df), dtype=np.int32)
    if "start_time" not in df.columns:
        return counts
    times_all = df["start_time"].values
    sub = df if mask is None else df.loc[mask]
    for _, g in sub.groupby(group_col, observed=True):
        idx = g.index.to_numpy()
        order = np.argsort(times_all[idx])
        idx = idx[order]
        t = times_all[idx]
        left = np.searchsorted(t, t - window, side="left")
        counts[idx] = np.arange(1, len(idx) + 1) - left
    return counts

def engineer_features(nf, hosts, is_inference=False):
    """
    Engineers features for the flow agent. 
    is_inference=True bypasses historical rolling window features, which must be provided externally.
    """
    if len(nf) == 0:
        return nf

    if "start_time" in nf.columns and not pd.api.types.is_datetime64_any_dtype(nf["start_time"]):
        nf["start_time"] = pd.to_datetime(nf["start_time"], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')

    if not is_inference:
        nf = nf.sort_values("start_time").reset_index(drop=True)

    h = hosts[["ip_address", "criticality", "host_type", "patch_level", "is_honeypot"]]
    nf = nf.merge(h.add_prefix("src_"), left_on="src_ip", right_on="src_ip_address", how="left")
    nf = nf.merge(h.add_prefix("dst_"), left_on="dst_ip", right_on="dst_ip_address", how="left")
    nf = nf.drop(columns=["src_ip_address", "dst_ip_address"], errors='ignore')
    
    nf["src_is_honeypot"] = nf["src_is_honeypot"].fillna(False).astype(int)
    nf["dst_is_honeypot"] = nf["dst_is_honeypot"].fillna(False).astype(int)
    
    for c in ["src_criticality", "dst_criticality", "src_host_type", "dst_host_type"]:
        nf[c] = nf[c].fillna("EXTERNAL_UNKNOWN")

    if "start_time" in nf.columns:
        nf["hour_npt"] = nf["start_time"].dt.hour
        nf["weekday"] = nf["start_time"].dt.dayofweek
        nf["day_of_month"] = nf["start_time"].dt.day
        nf["is_weekend"] = (nf["weekday"] >= 5).astype(int)
        nf["is_month_end_window"] = ((nf["day_of_month"] >= 25) | (nf["day_of_month"] <= 1)).astype(int)

    nf["bytes_ratio"] = nf["bytes_sent"] / (nf["bytes_recv"] + 1)
    nf["pkt_ratio"] = nf["packets_sent"] / (nf["packets_recv"] + 1)
    nf["avg_bytes_per_pkt_sent"] = nf["bytes_sent"] / (nf["packets_sent"] + 1)
    nf["avg_bytes_per_pkt_recv"] = nf["bytes_recv"] / (nf["packets_recv"] + 1)
    nf["total_bytes"] = nf["bytes_sent"] + nf["bytes_recv"]
    nf["total_packets"] = nf["packets_sent"] + nf["packets_recv"]

    if "tcp_flags" in nf.columns:
        nf["tcp_flags"] = nf["tcp_flags"].fillna("NONE")
        nf["is_syn_only"] = (nf["tcp_flags"] == "S").astype(int)

    nf["is_internal_src"] = nf["is_internal_src"].astype(int) if "is_internal_src" in nf.columns else 0
    nf["is_internal_dst"] = nf["is_internal_dst"].astype(int) if "is_internal_dst" in nf.columns else 0

    if not is_inference:
        print("[features] computing flows_per_src_5min ...")
        nf["flows_per_src_5min"] = rolling_count(nf, "src_ip", window_minutes=5)
        print("[features] computing swift_query_2min (hidden pattern #2 scope) ...")
        swift_mask = (nf["segment"] == "SWIFT") & (nf["dst_port"] == 1433)
        nf["swift_query_2min"] = rolling_count(nf, "src_ip", window_minutes=2, mask=swift_mask)
    else:
        for col in ["flows_per_src_5min", "swift_query_2min"]:
            if col not in nf.columns:
                print(f"WARNING: Stateful feature {col} missing during inference! Defaulting to 1.")
                nf[col] = 1

    return nf

def freq_encode_fit(df, cols):
    """Computes frequency distributions for categorical columns from the training set."""
    return {c: df[c].value_counts(normalize=True).to_dict() for c in cols}

def freq_encode_apply(df, cols, maps):
    """Applies fitted frequency distributions to a dataframe."""
    out = pd.DataFrame(index=df.index)
    for c in cols:
        out[c + "_freq"] = df[c].astype(object).map(maps[c]).fillna(0.0).astype(float)
    return out
