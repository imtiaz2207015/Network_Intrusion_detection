import pandas as pd
import glob

# Find all CSV files in current folder
csv_files = glob.glob("*.csv")
print("Found files:")
for f in csv_files:
    print(" -", f)

# Load and combine all CSVs
df_list = []
for file in csv_files:
    temp = pd.read_csv(file)
    df_list.append(temp)

df_all = pd.concat(df_list, ignore_index=True)

print("\nCombined Shape:", df_all.shape)
print("\nOverall Label distribution:")
print(df_all[' Label'].value_counts())

# Save combined dataset for later use
df_all.to_csv("combined_dataset.csv", index=False)
print("\nSaved as combined_dataset.csv")