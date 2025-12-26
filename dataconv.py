import pandas as pd
import os

parquet_dir = "Dataset/parquet"
csv_dir = "Dataset/csv"

os.makedirs(csv_dir, exist_ok=True)

for file in os.listdir(parquet_dir):
    if file.endswith(".parquet"):
        parquet_path = os.path.join(parquet_dir, file)
        csv_path = os.path.join(csv_dir, file.replace(".parquet", ".csv"))

        df = pd.read_parquet(parquet_path, engine="pyarrow")
        df.to_csv(csv_path, index=False)

        print(f"Converted: {file}")

print("All parquet files converted to CSV successfully")
