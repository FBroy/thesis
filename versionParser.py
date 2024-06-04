import os
import re
import json


malwareName = "Conti"
path = f"C:/Users/User/Documents/thesis/MalwareSamples/{malwareName}/anyrun"
files = [f for f in os.listdir(path) if os.path.isfile(f"{path}/{f}")]
osVersions = [7, 8.1, 10, 11]
allInformation = []

for file in files:
    information = {}
    for osVersion in osVersions:
        with open(f"{path}/results/{file.replace('.txt', '')}/{osVersion}.txt", 'r') as f:
            information[osVersion] = {}
            data = json.load(f)['data']
            information[osVersion]['startTime'] = data['analysis']['creation']

            # ---------------

            mitre = data['mitre']
            mitreCount = {}
            for m in mitre:
                if m['id'] not in mitreCount:
                    mitreCount[m['id']] = {}
                    mitreCount[m['id']]['count'] = 1
                    mitreCount[m['id']]['phase'] = set(m['phases'])
                else:
                    mitreCount[m['id']]['count'] += 1
                    mitreCount[m['id']]['phase'].update(m['phases'])
            for m in mitreCount:
                mitreCount[m]['phase'] = list(mitreCount[m]['phase'])
            mitreCount = dict(sorted(mitreCount.items()))
            information[osVersion]['mitre'] = mitreCount

            # ---------------

            incidents = data['incidents']
            incidentsCount = {}
            for i in incidents:
                if i['title'] not in incidentsCount:
                    incidentsCount[i['title']] = {}
                    incidentsCount[i['title']]['count'] = 1
                    incidentsCount[i['title']]['firstSeen'] = [i['firstSeen']]
                else:
                    incidentsCount[i['title']]['count'] += 1
                    incidentsCount[i['title']]['firstSeen'].append(i['firstSeen'])
            for i in incidentsCount:
                incidentsCount[i]['firstSeen'] = min(incidentsCount[i]['firstSeen'])
            incidentsCount = dict(sorted(incidentsCount.items()))
            information[osVersion]['incidents'] = incidentsCount

            # --------------
            
            modified = data['modified']
            encryptions = []
            ransomNotes = []
            for f in modified['files']:
                if re.search(r"\.[a-zA-Z]{5}(?!\S)", f['filename']):
                    encryptions.append(f['time'])
                elif re.search(r"\.txt", f['filename']):
                    ransomNotes.append(f['time'])
            information[osVersion]['modified'] = {}
            if len(encryptions) != 0:
                information[osVersion]['modified']['firstEncrypted'] = min(encryptions)
                information[osVersion]['modified']['lastEncrypted'] = max(encryptions)
            else:
                information[osVersion]['modified']['firstEncrypted'] = information[osVersion]['startTime']
                information[osVersion]['modified']['lastEncrypted'] = information[osVersion]['startTime']
            if len(ransomNotes) != 0:
                information[osVersion]['modified']['firstRansomNote'] = min(ransomNotes)
                information[osVersion]['modified']['lastRansomNote'] = max(ransomNotes)
            else:
                information[osVersion]['modified']['firstRansomNote'] = information[osVersion]['startTime']
                information[osVersion]['modified']['lastRansomNote'] = information[osVersion]['startTime']

            # ---------------
            
            counters = data['counters']
            information[osVersion]['counters'] = {'processes': counters['processes'], 'files': counters['files'], 'registry': counters['registry']}

    allInformation.append(information)

with open(f"{path}/results/extracted.txt", 'x') as f:
    f.write(json.dumps(allInformation, indent=4))
