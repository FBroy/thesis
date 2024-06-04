import vt
import os
import json
import time
import requests
from tqdm import tqdm


try:
    malwareName = "WannaCry"
    directory = f"MalwareSamples/{malwareName}/"
    parentDir = "C:/Users/User/Documents/thesis/"
    path = os.path.join(parentDir, directory)
except:
    pass

apiKey = "<api-key>"
client = vt.Client(apiKey)

with open(path + "results.txt", 'r') as results:
    lines = results.readlines()
    for line in tqdm(lines):
        sha256Hash = line.replace("\n", '')

        urls = [f"https://www.virustotal.com/api/v3/files/{sha256Hash}",
                f"https://www.virustotal.com/api/v3/files/{sha256Hash}/behaviour_summary",
                f"https://www.virustotal.com/api/v3/files/{sha256Hash}/behaviour_mitre_trees"]
        headers = {
            "x-apikey": f"{apiKey}",
        }
        try:
            with open(path + f"/downloadedInformation/truePositives/{sha256Hash}.txt", 'x') as f:
                f.write("[")
                for i in range(len(urls)):
                    data = requests.get(urls[i], headers=headers).json()
                    json.dump(data, f, indent=4)
                    if i != len(urls) - 1:
                        f.write(",")
                    # Sleep in order to make sure that we do not do more than 4 requests per minute
                    time.sleep(16)
                f.write("]")
        except:
            print(f"Something went wrong... {sha256Hash}")
            continue