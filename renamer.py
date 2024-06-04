import os
import pandas as pd


malwareName = "Conti"
workingDirectory = f"C:/Users/User/Downloads/MalwareSamples/{malwareName}/"
readDirectory = f"C:/Users/User/Downloads/MalwareSamples/output/output_{malwareName}.csv"
df = pd.read_csv(readDirectory)

for index, row in df.iterrows():
    if row['type'] != 'exe' and row['type'] != 'zip':
        continue
    try:
        os.rename(workingDirectory + row['sha256_hash'] + '.zip', workingDirectory + row['upload_date'].replace(' ', '-').replace(':', '-') + '-' + row['sha256_hash'] + '.zip')
    except:
        continue