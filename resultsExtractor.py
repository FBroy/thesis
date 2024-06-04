import os
import json
from virustotalParser import parse
import matplotlib.pyplot as plt
import matplotlib.dates as md
import datetime
plt.rcParams.update({'font.size': 18})

'''
'creation_date'
'file_information'              
'first_seen_itw'                
'first_submission_date'         
'analysis_results'              
'analysis_stats'                
'hashes'                        
'magic'                         
'names'                         
'packers'                       
'pe_info'                       
'threat_classification'         
'sandbox_verdicts'              
'sigma_rules'                   
'sigma_rules_stats'             
'size'                          
'file_tags'                     
'file_type'                     
'type'                          
'extension'                     
'type_tags'                     
'attack_techniques'             
'calls_highlighted'             
'command_executions'            
'crypto_algorithms_observed'    
'dns_lookups'                   
'files'                         
'files_attributes_changed'      
'ids_alerts'                    
'ip_traffic'                    
'hosts_file'                    
'mitre_attack_techniques'       
'modules_loaded'                
'mutexes'                       
'processes'                     
'registry_keys'                 
'signature_matches'             
'tags'                          
'verdicts'                      
'services'                      
'signals_observed'              
'text_decoded'                  
'text_highlighted'              
'windows_hidden'                
'windows_searched'              
'sandboxes'
'''

# First seen in the wild vs first submission vs creation (Timeline)
def makeGraph(fst, fsitw, creation, title):
    ax = plt.gca()
    xfmt = md.DateFormatter('%d/%m/%Y')
    ax.xaxis.set_major_formatter(xfmt)
    dates = [datetime.datetime.fromtimestamp(ts) for ts in fsitw.values()]
    values = [0.5 for _ in range(len(dates))]
    plt.subplots_adjust(bottom=0.2)
    plt.xticks(rotation=45)
    plt.scatter(dates, values, c='red', marker='x')
    dates=[datetime.datetime.fromtimestamp(ts) for ts in fst.values()]
    values = [-0.5 for _ in range(len(dates))]
    plt.scatter(dates, values, c='blue', marker="x")
    dates = [datetime.datetime.fromtimestamp(ts) for ts in creation.values()]
    values = [0 for _ in range(len(dates))]
    plt.scatter(dates, values, c='green', marker="x")
    plt.title(title)
    plt.legend(["First seen in the wild", "First submission", "Creation"])
    plt.yticks([])
    plt.xticks([datetime.datetime.fromtimestamp(v) for v in range(1577833200, 1704063601, 8415360)]) # From 01/01/2020 - 01/01/2024, 15 ticks
    plt.ylim([-1, 1])
    plt.xlabel("Date")
    plt.show()


# Graph for count per variant
# General use
def makeGraph2(variantsCount):
    plt.bar(list(variantsCount.keys()), list(variantsCount.values()))
    plt.xticks(rotation=90)
    for i in range(len(variantsCount)):
        plt.text(i, list(variantsCount.values())[i], list(variantsCount.values())[i], ha='center')
    plt.subplots_adjust(bottom=0.22)
    plt.title("Number of occurrences for Conti ransomware variants in dataset")
    plt.xlabel("Variant name")
    plt.ylabel("Number of occurrences in dataset")
    plt.show()


# General use
def makeOverTimeGraph(dates, title):
    ax = plt.gca()
    xfmt = md.DateFormatter('%d/%m/%Y')
    ax.xaxis.set_major_formatter(xfmt)
    y = []
    for i, value in enumerate(list(dates.values())[::-1]):
        values = [datetime.datetime.fromtimestamp(v) for v in value]
        y.append(i/len(dates))
        plt.scatter(values, [y[i] for _ in range(len(values))], marker='x', color='red')
    plt.xticks(rotation=45)
    dates = dict(sorted(dates.items()))
    plt.yticks(y)
    ax.grid(axis="y")
    plt.tick_params(axis='y', length=0)
    ax.axes.yaxis.set_ticklabels([])
    plt.title(f"{malwareName}: {title}")
    plt.xlabel("Date")
    plt.ylabel("Variant name")
    plt.subplots_adjust(left=0.15)
    plt.xticks([datetime.datetime.fromtimestamp(v) for v in range(1577833200, 1704063601, 8415360)]) # From 01/01/2020 - 01/01/2024, 15 ticks
    plt.yticks(y, list(dates.keys())[::-1])
    plt.show()


def firstSeenInTheWild(samples):
    fsitw = {}
    for s in samples:
        if s['first_seen_itw']:
            fsitw[s['hashes']['sha256']] = s['first_seen_itw']
    fsitw = dict(sorted(fsitw.items(), key=lambda item: item[1]))
    # print("First seen in the wild:")
    # print(len(fsitw))
    # for key, value in fsitw.items():
    #     date = datetime.datetime.fromtimestamp(value)
    #     print(f"{key}: {date:%d/%m/%Y}")
    return fsitw


def firstSubmission(samples):
    fst = {}
    for s in samples:
        if not s['first_seen_itw']:
            fst[s['hashes']['sha256']] = s['first_submission_date']
    fst = dict(sorted(fst.items(), key=lambda item: item[1]))
    # print("First submission:")
    # print(len(fst))
    # for key, value in fst.items():
    #     date = datetime.datetime.fromtimestamp(value)
    #     print(f"{key}: {date:%d/%m/%Y}")
    return fst


def creationDate(samples):
    creation = {}
    for s in samples:
        creation[s['hashes']['sha256']] = s['creation_date']
    creation = dict(sorted(creation.items(), key=lambda item: item[1]))
    # print("First creation:")
    # print(len(creation))
    # for key, value in creation.items():
    #     date = datetime.datetime.fromtimestamp(value)
    #     print(f"{key}: {date:%d/%m/%Y}")
    return creation


def getImports(samples, v='', startTime=0, timeInterval=0):
    # {'library_name': {'function': count, 'count': <count>}}
    imports = {}
    for a in samples:
        for h in a['pe_info']['import_list']:
            libraryName = h['library_name'].lower()
            if libraryName in imports.keys():
                imports[libraryName]['count'] += 1
                for f in h['imported_functions']:
                    functionName = f.lower()
                    if functionName in imports[libraryName].keys():
                        imports[libraryName][functionName] += 1
                    else:
                        imports[libraryName][functionName] = 1
            else:
                imports[libraryName] = {}
                imports[libraryName]['count'] = 1
                for f in h['imported_functions']:
                    imports[libraryName][f.lower()] = 1
    
    # print(f"{v}: {len(samples)} samples")
    # print(json.dumps(imports, indent=4))
    if v != '':
        with open(parentDir + "importsPerVariant.txt", 'a') as f:
            f.write(f"{v}: {len(samples)} samples\n")
            f.write(json.dumps(imports, indent=4))
            f.write("\n")
    else:
        with open(parentDir + "importsOverTime.txt", 'a') as f:
            f.write(f"{datetime.datetime.fromtimestamp(startTime).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp(startTime + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples\n")
            f.write(json.dumps(imports, indent=4))
            f.write("\n")


def getSandboxVerdicts(samples, v='', startTime=0, timeInterval=0):
    sandboxVerdicts = []
    for a in samples:
        verdict = {}
        verdict[a['hashes']['sha256']] = {}
        classifications = []
        for _, value in a['sandbox_verdicts'].items():
            if value['category'] in verdict[a['hashes']['sha256']].keys():
                verdict[a['hashes']['sha256']][value['category']] += 1
            else:
                verdict[a['hashes']['sha256']][value['category']] = 1
            if "malware_classification" in classifications:
                classifications.update(value['malware_classification'])
            else:
                classifications = set(value['malware_classification'])
        verdict[a['hashes']['sha256']]['malware_classification'] = list(classifications)
        sandboxVerdicts.append(verdict)

    # print(f"{v}: {len(samples)} samples")
    # print(json.dumps(sandboxVerdicts, indent=4))
    if v != '':
        with open(parentDir + "sandboxVerdictsPerVariant.txt", 'a') as f:
            f.write(f"{v}: {len(samples)} samples\n")
            f.write(json.dumps(sandboxVerdicts, indent=4))
            f.write("\n")
    else:
        with open(parentDir + "sandboxVerdictsOverTime.txt", 'a') as f:
            f.write(f"{datetime.datetime.fromtimestamp(startTime).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp(startTime + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples\n")
            f.write(json.dumps(sandboxVerdicts, indent=4))
            f.write("\n")

    return sandboxVerdicts


def getRansomNotes(samples, v='', startTime=0, timeInterval=0):
    ransomNotes = {}
    for a in samples:
        if a['text_decoded']:
            if a['text_decoded'][0] in list(ransomNotes.keys()):
                ransomNotes[a['text_decoded'][0]] += 1
            else:
                ransomNotes[a['text_decoded'][0]] = 1

    # print(f"{v}: {len(samples)} samples")
    # print(json.dumps(ransomNotes, indent=4))
    if v != '':
        with open(parentDir + "ransomNotesPerVariant.txt", 'a') as f:
            f.write(f"{v}: {len(samples)} samples\n")
            f.write(json.dumps(dict(sorted(ransomNotes.items())), indent=4))
            f.write("\n")
    else:
        with open(parentDir + "ransomNotesOverTime.txt", 'a') as f:
            f.write(f"{datetime.datetime.fromtimestamp(startTime).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp(startTime + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples\n")
            f.write(json.dumps(ransomNotes, indent=4))
            f.write("\n")


def getTags(samples, v='', startTime=0, timeInterval=0):
    # Same as file_tags but not as many 'useless' fields (such as peexe etc)
    tags = {}
    for a in samples:
        if a['tags']:
            for t in a['tags']:
                if t in list(tags.keys()):
                    tags[t] += 1
                else:
                    tags[t] = 1

    # print(f"{v}: {len(samples)} samples")
    # print(dict(sorted(tags.items())))
    if v != '':
        with open(parentDir + "tagsPerVariant.txt", 'a') as f:
            f.write(f"{v}: {len(samples)} samples\n")
            f.write(json.dumps(dict(sorted(tags.items())), indent=4))
            f.write("\n")
    else:
        with open(parentDir + "tagsOverTime.txt", 'a') as f:
            f.write(f"{datetime.datetime.fromtimestamp(startTime).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp(startTime + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples\n")
            f.write(json.dumps(tags, indent=4))
            f.write("\n")


def getSignatures(samples, v='', startTime=0, timeInterval=0):
    signatures = {}
    for a in samples:
        if a['signature_matches']:
            for s in a['signature_matches']:
                if s in list(signatures.keys()):
                    signatures[s] += 1
                else:
                    signatures[s] = 1

    # print(f"{v}: {len(samples)} samples")
    # print(json.dumps(signatures, indent=4))
    if v != '':
        with open(parentDir + "signaturesPerVariant.txt", 'a') as f:
            f.write(f"{v}: {len(samples)} samples\n")
            f.write(json.dumps(signatures, indent=4))
            f.write("\n")
    else:
        with open(parentDir + "signaturesOverTime.txt", 'a') as f:
            f.write(f"{datetime.datetime.fromtimestamp(startTime).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp(startTime + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples\n")
            f.write(json.dumps(signatures, indent=4))
            f.write("\n")


def getTacticsAndTechniques(samples, v='', startTime=0, timeInterval=0):
    # Differences between mitre_attack_techniques results and sandboxes results are that some techniques do not exist (anymore)
    # Use the sandboxes one, as those also contain the tactics next to the techniques
    tacticsAndTechniques = {}

    for a in samples:
        tacticsFound = []
        techniquesFound = []
        for start in a['sandboxes'].values():
            for tactic in start['tactics']:
                tactic_id = tactic['id']
                tactic_desc = tactic['description']
                tactic_name = tactic['name']
                if tactic_id in list(tacticsAndTechniques.keys()):
                    if tactic_id not in tacticsFound:
                        tacticCount = tacticsAndTechniques[tactic_id]['count'] + 1
                        tacticsFound.append(tactic_id)
                    else:
                        tacticCount = tacticsAndTechniques[tactic_id]['count']
                    techniques = tacticsAndTechniques[tactic_id]['techniques']
                else:
                    tacticCount = 1
                    techniques = []
                    tacticsFound.append(tactic_id)

                for technique in tactic['techniques']:
                    technique_id = technique['id']
                    technique_desc = technique['description']
                    technique_name = technique['name']
                    found = False
                    for i in range(len(techniques)):
                        if technique_id in list(techniques[i].keys()):
                            if technique_id not in techniquesFound:
                                techniques[i][technique_id]['count'] += 1
                                techniquesFound.append(technique_id)
                            found = True
                            break
                    if not found:
                        techniques.append({technique_id: {'name': technique_name, 'count': 1, 'description': technique_desc}})
                        techniquesFound.append(technique_id)
                tacticsAndTechniques[tactic_id] = {
                    'name': tactic_name,
                    'count': tacticCount,
                    'description': tactic_desc,
                    'techniques': techniques
                }
    if v != '':
        with open(parentDir + "tacticsAndTechniquesPerVariant.txt", 'a') as f:
            f.write(f"{v}: {len(samples)} samples\n")
            f.write(json.dumps(tacticsAndTechniques, indent=4))
            f.write("\n")
    else:
        with open(parentDir + "tacticsAndTechniquesOverTime.txt", 'a') as f:
            f.write(f"{datetime.datetime.fromtimestamp(startTime).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp(startTime + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples\n")
            f.write(json.dumps(tacticsAndTechniques, indent=4))
            f.write("\n")


def getVariantsCount(samples):
    variantsCount = {}
    for v in samples:
        variant = v['variant'].replace("Ransom:Win", '')
        try:
            variantsCount[variant] += 1
        except:
            variantsCount[variant] = 1

    variantsCount = dict(sorted(variantsCount.items(), key=lambda item: item[1])[::-1])
    # print(variantsCount)

    makeGraph2(variantsCount)

    return variantsCount


def getSamplesByVariant(allSamples, allVariants):
    sandboxVerdicts = []
    for variant in allVariants:
        samples = []
        for sample in allSamples:
            if sample['variant'] == variant:
                samples.append(sample)
        sbv = statsPerVariant(samples, variant)

        classifications = {'malicious': 0, 'harmless': 0, 'undetected': 0, 'total': 0}
        tags = {}
        for v in sbv:
            for key, value in v.get(list(v.keys())[0]).items():
                if key == 'malware_classification':
                    for t in value:
                        if t in tags:
                            tags[t] += 1
                        else:
                            tags[t] = 1
                else:
                    classifications['total'] += value
                    classifications[key] += value
        sandboxVerdicts.append({variant: {'malware_classification': classifications, 'tags': tags}})

    with open(parentDir + 'sandboxVerdictsPerVariantGrouped.txt', 'a') as f:
        f.write(json.dumps(sandboxVerdicts, indent=4))
        f.write('\n')

def statsPerVariant(samples, v):
    # Use the grouped samples to generate the stats by calling the functions one by one
    if (len(samples) > 10):
        fsitw = firstSeenInTheWild(samples)
        fst = firstSubmission(samples)
        creation = creationDate(samples)
        makeGraph(fsitw, fst, creation, f"{malwareName} ransomware over time. Variant {v}")
    # getImports(samples, v=v)
    # sandboxVerdicts = getSandboxVerdicts(samples, v=v)
    # getRansomNotes(samples, v=v)
    # getTags(samples, v=v)
    # getSignatures(samples, v=v)
    # getTacticsAndTechniques(samples, v=v)
    # return sandboxVerdicts
    pass


def getSamplesByTimeInterval(allSamples, timeInterval, choice):
    field = 'creation_date' if choice == 0 else 'first_submission_date'
    allSamplesSorted = sorted(allSamples, key=lambda x: (x[field]))
    samples = []
    counter = 1
    sandboxVerdicts = []
    minimumTime = allSamplesSorted[0][field]
    for sample in allSamplesSorted:
        if sample[field] < minimumTime + timeInterval * counter:
            samples.append(sample)
        else:
            print(f"{datetime.datetime.fromtimestamp(minimumTime + timeInterval * counter).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp((minimumTime + timeInterval * counter) + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples")
            sbv = statsPerTimeInterval(samples, minimumTime + timeInterval * counter, timeInterval, field)
            counter += 1
            samples = [sample]

            classifications = {'malicious': 0, 'harmless': 0, 'undetected': 0, 'total': 0}
            tags = {}
            for v in sbv:
                for key, value in v.get(list(v.keys())[0]).items():
                    if key == 'malware_classification':
                        for t in value:
                            if t in tags:
                                tags[t] += 1
                            else:
                                tags[t] = 1
                    else:
                        classifications['total'] += value
                        classifications[key] += value
            sandboxVerdicts.append({f"{datetime.datetime.fromtimestamp(minimumTime + timeInterval * counter).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp((minimumTime + timeInterval * counter) + timeInterval).strftime('%d/%m/%Y')}": {'malware_classification': classifications, 'tags': tags}})

    # print(f"{datetime.datetime.fromtimestamp(minimumTime + timeInterval * counter).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp((minimumTime + timeInterval * counter) + timeInterval).strftime('%d/%m/%Y')}: {len(samples)} samples")
    # sbv = statsPerTimeInterval(samples, minimumTime + timeInterval * counter, timeInterval, field)
    # counter += 1
    # samples = [sample]

    # classifications = {'malicious': 0, 'harmless': 0, 'undetected': 0, 'total': 0}
    # tags = {}
    # for v in sbv:
    #     for key, value in v.get(list(v.keys())[0]).items():
    #         if key == 'malware_classification':
    #             for t in value:
    #                 if t in tags:
    #                     tags[t] += 1
    #                 else:
    #                     tags[t] = 1
    #         else:
    #             classifications['total'] += value
    #             classifications[key] += value
    # sandboxVerdicts.append({f"{datetime.datetime.fromtimestamp(minimumTime + timeInterval * counter).strftime('%d/%m/%Y')} - {datetime.datetime.fromtimestamp((minimumTime + timeInterval * counter) + timeInterval).strftime('%d/%m/%Y')}": {'malware_classification': classifications, 'tags': tags}})

    # ------------------
    statsPerTimeInterval(samples, minimumTime + timeInterval * counter, timeInterval, field)
    # ------------------

    # with open(parentDir + 'sandboxVerdictsOverTimeGrouped.txt', 'a') as f:
    #     f.write(json.dumps(sandboxVerdicts, indent=4))
    #     f.write('\n')


def statsPerTimeInterval(samples, startTime, timeInterval, field):
    # getImports(samples, startTime=startTime, timeInterval=timeInterval)
    # sandboxVerdicts = getSandboxVerdicts(samples, startTime=startTime, timeInterval=timeInterval)
    # return sandboxVerdicts
    # getRansomNotes(samples, startTime=startTime, timeInterval=timeInterval)
    # getTags(samples, startTime=startTime, timeInterval=timeInterval)
    # getSignatures(samples, startTime=startTime, timeInterval=timeInterval)
    # getTacticsAndTechniques(samples, startTime=startTime, timeInterval=timeInterval)
    pass


def getVariantsOverTime(samples):
    fsitwDates = {}
    fstDates = {}
    creation = {}
    for s in samples:
        variant = s['variant'].replace("Ransom:Win", "")
        if s['first_seen_itw']:
            fsitwDates.setdefault(variant, [])
            fsitwDates[variant.replace("Ransom:Win", "")].append(s['first_seen_itw'])
        else:
            fstDates.setdefault(variant, [])
            fstDates[variant].append(s['first_submission_date'])
        if s['creation_date']:
            creation.setdefault(variant, [])
            creation[variant].append(s['creation_date'])

    # print(fsitwDates)
    # print(fstDates)
    # print(creation)
    makeOverTimeGraph(fsitwDates, "First seen in the wild per variant")
    makeOverTimeGraph(fstDates, "First submission date per variant")
    makeOverTimeGraph(creation, "Creation date per variant")

    return fsitwDates, fstDates, creation


def getAllVariants(samples):
    allVariants = []
    for variant in samples:
        v = variant['variant']
        if v not in allVariants:
            allVariants.append(v)
    return allVariants


malwareName = "Ryuk"
directory = f"downloadedInformation/truePositives/"
# Windows
parentDir = f"C:/Users/User/Documents/thesis/MalwareSamples/{malwareName}/"
# Linux
# parentDir = f"/home/frank/Documents/thesis/MalwareSamples/{malwareName}/"
path = os.path.join(parentDir, directory)

extractedInformation = parse(path)
allVariants = getAllVariants(extractedInformation)

# Call the functions you need for the specific information
# statsPerVariant(extractedInformation, "All")
# getVariantsOverTime(extractedInformation)
# getVariantsCount(extractedInformation)
# extactedInformationByVariant = getSamplesByVariant(extractedInformation, allVariants)
# 3 months = 7776000
# 6 months = 15638400
# 5 years = 157784760
# 0 = creation date, 1 = submission date, Not doable with fsitw, as not every sample has this
extractedInformationByTimeInterval = getSamplesByTimeInterval(extractedInformation, 1577847600, 0)