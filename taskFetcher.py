import os
import json
from tqdm import tqdm


apiKey = 'Mviof62mda6Q4KzDdumajmmiCsXhKCg7HtJmnRHF'
malwareName = "Conti"
dir = f"C:/Users/User/Documents/thesis/MalwareSamples/{malwareName}/anyrun"
files = [f for f in os.listdir(dir) if os.path.isfile(f)]
osVersions = [7, 8.1, 10, 11]
for file in tqdm(files):
    with open(f"{dir}/{file}") as f:
        lines = f.readlines()
        counter = 0
        os.mkdir(f"{dir}/results/{file}")
        for line in lines:
            taskid = line.replace("\n", '')
            r = f'curl --silent -H "Authorization: API-Key {apiKey}" "https://api.any.run/v1/analysis/{taskid}"'
            result = os.popen(r)
            result._stream.reconfigure(encoding='utf-8', newline="")
            result = result.read()
            try:
                with open(f"{dir}/results/{file}/{osVersions[counter]}.txt", 'x') as fil:
                    fil.write(json.dumps(json.loads(result), indent=4))
            except:
                print(file, osVersions[counter])
            counter += 1