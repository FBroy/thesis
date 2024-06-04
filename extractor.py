import os


malwareName = "Ryuk"
allFiles = os.listdir(f"/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/allRyukSamples/")

for f in allFiles:
    if not ".zip" in f and not ".7z" in f:
        continue
    os.system(f"7z x /home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/allRyukSamples/{f} -pinfected -o/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/allRyukSamples/")