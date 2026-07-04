import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import numpy as np

# Create dummy df
df = pd.DataFrame({
    'username': ['B', 'A', 'B', 'A', 'C'],
    'timestamp': pd.to_datetime(['2023-01-01 10:00:00', '2023-01-01 10:05:00', '2023-01-01 10:02:00', '2023-01-01 10:01:00', '2023-01-01 10:00:00']),
    'val': [1, 2, 3, 4, 5]
})

# Sort exactly like train_behavior.py does
df = df.sort_values(by=['username', 'timestamp']).reset_index(drop=True)
print("Sorted df:")
print(df)

# Rolling exactly like train_behavior.py does
temp = df[['timestamp', 'username']].copy()
temp['count_val'] = 1.0
temp.set_index('timestamp', inplace=True)

rolling_res = temp.groupby('username')['count_val'].rolling('5min').count()
print("\nRolling Result:")
print(rolling_res)

# Does .values perfectly match?
f_query_rate = rolling_res.values
print("\nValues array:")
print(f_query_rate)

# Let's map it safely to be absolutely sure
safe_rolling = temp.groupby('username', sort=False)['count_val'].rolling('5min').count().values
print("\nSafe values array (sort=False):")
print(safe_rolling)
