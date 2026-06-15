import numpy as np
import pandas as pd

np.random.seed(42) # keeps random values consistent
price_changes = np.random.normal(0.5, 2, 1000) # mean= 0.5 , std_dev =2
prices = 100 + np.cumsum(price_changes)

# Port to Pandas
time_index = pd.date_range(start="2026-01-01", periods=1000, freq='h')
portfolio_df = pd.DataFrame(data={'Asset_Price': prices}, index=time_index)

# moving average 5 hours enough? yup
portfolio_df['5_Hour_Moving_Avg'] = portfolio_df['Asset_Price'].rolling(window=5).mean()

#deviation calculating
price_deviation = np.abs(portfolio_df['Asset_Price'] - portfolio_df['5_Hour_Moving_Avg'])
spike_constraint = price_deviation > 3.0
#check
anomalies = portfolio_df[spike_constraint]

print("--- Total Rows Evaluated ---")
print(len(portfolio_df))
print("\n--- Detected Volatility Spikes (First 5 Rows) ---")
print(anomalies.head(5))