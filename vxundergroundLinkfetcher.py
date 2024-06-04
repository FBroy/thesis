import re
import requests


malwareName = "Ryuk"
r = requests.get("https://vx-underground.org/Samples/Families/REvil")
matches = re.findall(rf"(?:https:\/\/samples\.vx-underground\.org\/Samples\/Families\/{malwareName}\/.{64}.7z)", r.content.decode())
with open(f"{malwareName}Links.txt", 'x') as f:
    for link in matches:
        f.write(link + "\n")