import pandas as pd
import numpy as np

print("Loading combined dataset...")
df = pd.read_csv("combined_dataset.csv")

# Clean column names (remove leading/trailing spaces)
df.columns = df.columns.str.strip()

print("Shape before cleaning:", df.shape)

# Replace infinite values with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop rows with any NaN
df.dropna(inplace=True)

print("Shape after cleaning:", df.shape)

# Create binary label: 0 = BENIGN, 1 = ATTACK
df['Binary_Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

print("\nBinary label distribution:")
print(df['Binary_Label'].value_counts())

# Save cleaned dataset
df.to_csv("cleaned_dataset.csv", index=False)
print("\nSaved as cleaned_dataset.csv")