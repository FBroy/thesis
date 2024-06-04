import os


malwareName = "Ryuk"
allFiles = os.listdir(f"/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/allRyukSamplesWithExe/")
truePositives = []
with open(f"/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/results.txt", 'r') as f:
    lines = f.readlines()
    for line in lines:
        name = line.replace("\n", '')
        if not name in truePositives:
            truePositives.append(name)

for f in allFiles:
    if f.replace(".7z", '').replace(".zip", '').replace('.exe', '') not in truePositives:
        os.remove(f"/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/allRyukSamplesWithExe/{f}")