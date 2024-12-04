import pandas as pd


file1 = r"C:\Users\91637\Downloads\all_good.csv"  
file2 = r"C:\Users\91637\Downloads\all_bad.csv"  
all_queries = r"C:\Users\91637\Downloads\whole_queries.csv"


df1 = pd.read_csv(file1)
df2 = pd.read_csv(file2)


merged_df = pd.concat([df1, df2], ignore_index=True)

merged_df.to_csv(all_queries, index=False)

print("Files merged successfully into 'all_queries.csv'.")
