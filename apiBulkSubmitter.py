import os
import json
import time
from tqdm import tqdm


apiKey = '<api-key>'
malwareName = "Conti"
path = f"/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}"
files = os.listdir(path)
osVersions = [7, 8.1, 10, 11]

for f in tqdm(files):
    if ".exe" not in f:
        continue
    taskIds = []
    counter = 0
    while counter < 4:
        r = f"curl -XPOST -H 'Authorization: API-Key {apiKey}' -F 'file=@{path}/{f}' -F 'env_os=windows' -F 'env_bitness=64' -F 'env_version={osVersions[counter]}' -F 'env_type=clean' -F 'opt_timeout=90' -F 'obj_ext_startfolder=desktop' 'https://api.any.run/v1/analysis' --silent"
        result = json.loads(os.popen(r).read())
        print(result)
        if not result['error']:
            taskIds.append(result['data']['taskid'])
            counter += 1
            time.sleep(100)
    with open(f"{path}/anyrun/taskIds/{f.replace('.exe', '')}.txt", 'x') as tids:
        for taskid in taskIds:
            tids.write(f"{taskid}\n")
