import os


# Replace this file with the correct one (the numbers at the end may differ)
logpath = "C:/ProgramData/Microsoft/Windows Defender/Support/MPDetection-20240212-143841.log"
directory = "C:/Users/User/Desktop/downloadedFiles"
fileNames = os.listdir(directory)

with open(logpath, 'r', encoding='utf-16') as f:
    lines = f.readlines()
    for fileName in fileNames:
        found = False
        if ".exe" in fileName:
            continue
        for line in lines:
            if fileName.replace(".7z", '').replace(".zip", '') in line:
                l = line.split()[2]
                print(f"{fileName}: {l}")
                found = True
                break
            
        if not found:
            print(f"{fileName}: Not found")
        