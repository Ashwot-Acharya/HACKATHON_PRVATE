import pandas as pd

print("Loading data...")
nf = pd.read_csv("data/netflow_records.csv", usecols=["flow_id", "bytes_recv"])
labels = pd.read_csv("data/ids_labels_train.csv")

df = nf.merge(labels, on="flow_id")
print("\nDistribution of bytes_recv by is_attack:")
print(df.groupby("is_attack")["bytes_recv"].describe())
