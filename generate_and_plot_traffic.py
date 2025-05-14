import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Generate synthetic traffic data
np.random.seed(0)
data_points = 1440  # Number of data points (e.g., 1440 minutes in a day)
traffic_data = np.random.poisson(lam=50, size=data_points)  # Generate traffic counts with random noise

# Introduce some anomalies by adding unusually high values
anomaly_indices = np.random.choice(data_points, size=10, replace=False)
traffic_data[anomaly_indices] = traffic_data[anomaly_indices] * 5  # Increase anomalous traffic

# Create a DataFrame and save to CSV
data = pd.DataFrame({'Traffic': traffic_data})
data.to_csv('Synthetic-Traffic-Data.csv', index=False)
print("Synthetic traffic data saved to 'Synthetic-Traffic-Data.csv'")

# Create figure and plot
fig, ax = plt.subplots(figsize=(12, 5))
ax.plot(data['Traffic'], label='Traffic Data', color='blue')
ax.axhline(y=data['Traffic'].mean(), color='r', linestyle='--', label='Mean Traffic')
ax.scatter(anomaly_indices, data.loc[anomaly_indices, 'Traffic'], color='red', label='Anomalies', zorder=3)
ax.legend()
ax.set_title('Synthetic Website Traffic Over Time')
ax.set_xlabel('Time (Minutes)')
ax.set_ylabel('Traffic Count')

# Move text to the **top-right** corner, fully outside the plot
fig.text(
    0.985, 0.94,  # Increase the y-value to move text a bit higher
    "⚠️ This plot is for training purposes only ⚠️",
    fontsize=12, color='red', fontweight='bold',
    ha='right', va='top',
    bbox=dict(facecolor='yellow', alpha=0.5, edgecolor='red', boxstyle='round,pad=0.5')
)

# Change the window title
plt.get_current_fig_manager().set_window_title("Traffic Data Visualization")

plt.show()
