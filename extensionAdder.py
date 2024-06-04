import os


allFiles = os.listdir("/home/frank/Documents/thesisScripts/MalwareSamples/Ryuk/allRyukSamples/")
for f in allFiles:
    if ".7z" in f or ".zip" in f or ".exe" in f:
        continue
    os.rename(f"/home/frank/Documents/thesisScripts/MalwareSamples/Ryuk/allRyukSamples/{f}", f"/home/frank/Documents/thesisScripts/MalwareSamples/Ryuk/allRyukSamples/{f}.exe")