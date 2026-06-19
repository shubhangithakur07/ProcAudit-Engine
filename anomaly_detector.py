""" 
 Project: Anomaly Detection Engine (IITK B.Cyber)
 Author: Shubhangithakur07
 Description: Vectorized volatility spike detection for telemetry streams.
 Note: Keep the threshold tuned to 3.0 for now; increase if false 
 positives spike on volatile days.
 
""" 
import numpy as np
import pandas as pd

np.random.seed(42) # need to keep random values consistent
price_changes = np.random.normal(0.5, 2, 1000) # mean= 0.5 , std_dev =2 will match noise patterns 
prices = 100 + np.cumsum(price_changes)

# Port to pandas for time series stuff
time_index = pd.date_range(start="2026-01-01", periods=1000, freq='h')
strm_df = pd.DataFrame(data={'Asset_Price': prices}, index=time_index)

# moving average 5 hours enough? yup
strm_df['5_Hour_Moving_Avg'] = strm_df['Asset_Price'].rolling(window=5).mean()

#deviation calculating 
#threshold 3.0 enough to filter current noise yes
price_deviation = np.abs(strm_df['Asset_Price'] - strm_df['5_Hour_Moving_Avg'])
spike_constraint = price_deviation > 3.0
#check
anomalies = strm_df[spike_constraint]

print("--- Total Rows Evaluated ---")
print(len(strm_df))
print("\n--- Detected Volatility Spikes (First 5 Rows) ---")
print(anomalies.head(5))


#FIX:output can be empty if threshold value too high 