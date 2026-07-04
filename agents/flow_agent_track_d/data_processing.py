import pandas as pd
try:
    from agents.flow_agent_track_d.flow_utils import engineer_features, CATEGORICAL_COLS
except ModuleNotFoundError:
    from flow_utils import engineer_features, CATEGORICAL_COLS

def load_data(netflow_path="data/netflow_records.csv", labels_path="data/ids_labels_train.csv", hosts_path="data/host_profiles.csv"):
    print(f"[load] {netflow_path} ...")
    nf = pd.read_csv(netflow_path)
    nf["start_time"] = pd.to_datetime(nf["start_time"], format="%Y-%m-%d %H:%M:%S.%f")
    print(f"[load] nf shape={nf.shape}")

    print(f"[load] {labels_path} ...")
    labels = pd.read_csv(labels_path)
    labels["is_attack"] = labels["is_attack"].astype(bool)
    print(f"[load] labels shape={labels.shape}, attack_rate={labels['is_attack'].mean():.4f}")

    print(f"[load] {hosts_path} ...")
    hosts = pd.read_csv(hosts_path)
    hosts = hosts.drop_duplicates(subset="ip_address", keep="last")
    print(f"[load] hosts shape={hosts.shape}")

    return nf, labels, hosts

def check_and_drop_leak_column(nf, labels):
    if "flow_label" not in nf.columns:
        return nf
    populated = nf["flow_label"].notna().sum()
    print(f"[leak check] flow_label present in netflow_records: populated={populated}/{len(nf)}")
    if populated > len(labels) * 1.05:
        print("[leak check] WARNING: flow_label is populated for more rows than the released "
              "label file \u2014 this almost certainly leaks hidden-eval ground truth. Dropping regardless.")
    else:
        print("[leak check] flow_label populated count is close to the released label count \u2014 "
              "still dropping it, only ids_labels_train.is_attack is trusted as ground truth.")
    return nf.drop(columns=["flow_label"])

def temporal_split(nf, labels, train_quantile=0.70, val_quantile=0.85):
    nf = nf.merge(labels[["flow_id", "is_attack", "attack_category"]], on="flow_id", how="left")
    labeled_mask = nf["is_attack"].notna()
    n_labeled = labeled_mask.sum()
    print(f"[split] labeled rows={n_labeled} ({n_labeled/len(nf):.2%} of {len(nf)})")

    zero_day_ct = (nf.loc[labeled_mask, "attack_category"] == "ZERO_DAY_EXPLOIT").sum()
    print(f"[split] ZERO_DAY_EXPLOIT rows in released labels: {zero_day_ct}")

    t_train_end = nf.loc[labeled_mask, "start_time"].quantile(train_quantile)
    t_val_end = nf.loc[labeled_mask, "start_time"].quantile(val_quantile)
    print(f"[split] train_end={t_train_end}  val_end={t_val_end}")

    if_train_mask = nf["start_time"] <= t_train_end         
    if_val_mask = (nf["start_time"] > t_train_end) & (nf["start_time"] <= t_val_end)
    if_test_mask = nf["start_time"] > t_val_end

    train_mask = labeled_mask & if_train_mask
    val_mask = labeled_mask & if_val_mask
    test_mask = labeled_mask & if_test_mask

    print(f"[split] supervised train={train_mask.sum()} val={val_mask.sum()} test={test_mask.sum()}")

    return nf, {
        "if_train": if_train_mask, "if_val": if_val_mask, "if_test": if_test_mask,
        "train": train_mask, "val": val_mask, "test": test_mask,
        "t_train_end": t_train_end, "t_val_end": t_val_end,
    }

def process_data(netflow_path="data/netflow_records.csv", labels_path="data/ids_labels_train.csv", hosts_path="data/host_profiles.csv", train_quantile=0.70, val_quantile=0.85):
    nf, labels, hosts = load_data(netflow_path, labels_path, hosts_path)
    nf = check_and_drop_leak_column(nf, labels)
    nf = engineer_features(nf, hosts, is_inference=False)
    nf, masks = temporal_split(nf, labels, train_quantile, val_quantile)
    
    categorical_levels = {c: nf[c].astype("category").cat.categories for c in CATEGORICAL_COLS}
    for c in CATEGORICAL_COLS:
        nf[c] = pd.Categorical(nf[c], categories=categorical_levels[c])
        
    return nf, masks, categorical_levels
