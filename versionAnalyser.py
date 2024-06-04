import json
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
plt.rcParams.update({'font.size': 18})


malwareName = "Conti"
# Windows
path = f"C:/Users/User/Documents/thesis/MalwareSamples/{malwareName}/anyrun/results/extracted.txt"
# Linux
# path = f"/home/frank/Documents/thesis/MalwareSamples/{malwareName}/anyrun/results/extracted.txt"
with open(path, 'r') as f:
    information = json.loads(f.read())

osVersions = ['7', '8.1', '10', '11']
firstEncrypted = [[], [], [], []]
lastEncrypted = [[], [], [], []]
firstRansomNote = [[], [], [], []]
lastRansomNote = [[], [], [], []]

for i in information:
    counter = 0
    while counter < 4:
        firstEncrypted[counter].append((i[osVersions[counter]]['modified']['firstEncrypted'] - i[osVersions[counter]]['startTime'])/1000)
        lastEncrypted[counter].append((i[osVersions[counter]]['modified']['lastEncrypted'] - i[osVersions[counter]]['startTime'])/1000)
        firstRansomNote[counter].append((i[osVersions[counter]]['modified']['firstRansomNote'] - i[osVersions[counter]]['startTime'])/1000)
        lastRansomNote[counter].append((i[osVersions[counter]]['modified']['lastRansomNote'] - i[osVersions[counter]]['startTime'])/1000)
        counter += 1

def makeGraph(firstEncrypted, lastEncrypted, firstRansomNote, lastRansomNote, title1, title2, title3, title4):
    times = list(range(143))
    _, axs = plt.subplots(2, 2, figsize=(10, 8))
    axs[0, 0].scatter(times, firstEncrypted[0], c='red', marker='x')
    axs[0, 0].scatter(times, firstEncrypted[1], c='blue', marker='x')
    axs[0, 0].scatter(times, firstEncrypted[2], c='green', marker='x')
    axs[0, 0].scatter(times, firstEncrypted[3], c='purple', marker='x')
    axs[0, 0].set_title(title1)
    axs[0, 0].legend(["Windows 7", "Windows 8.1", "Windows 10", "Windows 11"])
    axs[0, 0].set_xticks([])
    axs[0, 0].set_ylabel("Time in seconds")

    axs[0, 1].scatter(times, lastEncrypted[0], c='red', marker='x')
    axs[0, 1].scatter(times, lastEncrypted[1], c='blue', marker='x')
    axs[0, 1].scatter(times, lastEncrypted[2], c='green', marker='x')
    axs[0, 1].scatter(times, lastEncrypted[3], c='purple', marker='x')
    axs[0, 1].set_title(title2)
    axs[0, 1].legend(["Windows 7", "Windows 8.1", "Windows 10", "Windows 11"])
    axs[0, 1].set_xticks([])
    axs[0, 1].set_ylabel("Time in seconds")

    axs[1, 0].scatter(times, firstRansomNote[0], c='red', marker='x')
    axs[1, 0].scatter(times, firstRansomNote[1], c='blue', marker='x')
    axs[1, 0].scatter(times, firstRansomNote[2], c='green', marker='x')
    axs[1, 0].scatter(times, firstRansomNote[3], c='purple', marker='x')
    axs[1, 0].set_title(title3)
    axs[1, 0].legend(["Windows 7", "Windows 8.1", "Windows 10", "Windows 11"])
    axs[1, 0].set_xticks([])
    axs[1, 0].set_ylabel("Time in seconds")

    axs[1, 1].scatter(times, lastRansomNote[0], c='red', marker='x')
    axs[1, 1].scatter(times, lastRansomNote[1], c='blue', marker='x')
    axs[1, 1].scatter(times, lastRansomNote[2], c='green', marker='x')
    axs[1, 1].scatter(times, lastRansomNote[3], c='purple', marker='x')
    axs[1, 1].set_title(title4)
    axs[1, 1].legend(["Windows 7", "Windows 8.1", "Windows 10", "Windows 11"])
    axs[1, 1].set_xticks([])
    axs[1, 1].set_ylabel("Time in seconds")

    plt.tight_layout()
    plt.show()

for i in range(4):
    print(osVersions[i])
    print(min([e for e in firstEncrypted[i] if e != 0]))
    print(max([e for e in firstEncrypted[i] if e != 0]))
    print(sum([e for e in firstEncrypted[i] if e != 0]) / len([e for e in firstEncrypted[i] if e != 0]))
    print(np.median([e for e in firstEncrypted[i] if e != 0]))

for i in range(4):
    print(osVersions[i])
    print(min([e for e in lastEncrypted[i] if e != 0]))
    print(max([e for e in lastEncrypted[i] if e != 0]))
    print(sum([e for e in lastEncrypted[i] if e != 0]) / len([e for e in lastEncrypted[i] if e != 0]))
    print(np.median([e for e in lastEncrypted[i] if e != 0]))

for i in range(4):
    print(osVersions[i])
    print(min([e for e in firstRansomNote[i] if e != 0]))
    print(max([e for e in firstRansomNote[i] if e != 0]))
    print(sum([e for e in firstRansomNote[i] if e != 0]) / len([e for e in firstRansomNote[i] if e != 0]))
    print(np.median([e for e in firstRansomNote[i] if e != 0]))

for i in range(4):
    print(osVersions[i])
    print(min([e for e in lastRansomNote[i] if e != 0]))
    print(max([e for e in lastRansomNote[i] if e != 0]))
    print(sum([e for e in lastRansomNote[i] if e != 0]) / len([e for e in lastRansomNote[i] if e != 0]))
    print(np.median([e for e in lastRansomNote[i] if e != 0]))
makeGraph(firstEncrypted, lastEncrypted, firstRansomNote, lastRansomNote, "First encryption", "Last encryption", "First ransom note", "Last ransom note")

def createDensityPlot(osVersions, firstEncrypted, lastEncrypted, firstRansomNote, lastRansomNote, title1, title2, title3, title4):
    data1 = []
    for version, values in zip(osVersions, firstEncrypted):
        for value in values:
            data1.append({'Windows Version': version, 'Time': value})
    df1 = pd.DataFrame(data1)
    df1 = df1.drop(index=df1[(df1 == 0).any(axis=1)].index)

    data2 = []
    for version, values in zip(osVersions, lastEncrypted):
        for value in values:
            data2.append({'Windows Version': version, 'Time': value})
    df2 = pd.DataFrame(data2)
    df2 = df2.drop(index=df2[(df2 == 0).any(axis=1)].index)

    data3 = []
    for version, values in zip(osVersions, firstRansomNote):
        for value in values:
            data3.append({'Windows Version': version, 'Time': value})
    df3 = pd.DataFrame(data3)
    df3 = df3.drop(index=df3[(df3 == 0).any(axis=1)].index)

    data4 = []
    for version, values in zip(osVersions, lastRansomNote):
        for value in values:
            data4.append({'Windows Version': version, 'Time': value})
    df4 = pd.DataFrame(data4)
    df4 = df4.drop(index=df4[(df4 == 0).any(axis=1)].index)

    _, axs = plt.subplots(2, 2, figsize=(10, 8))

    var_x = 'Time'
    var_split = 'Windows Version'

    sns.set_theme(style="darkgrid", font_scale=2)
    sns.kdeplot(data=df1, x=var_x, hue=var_split, common_norm=False, palette=['red', 'green', 'blue', 'orange'], fill=False, ax=axs[0, 0])
    axs[0, 0].set_title(title1)
    axs[0, 0].set_xlabel('Time in seconds')
    axs[0, 0].set_ylabel('Density')
    
    sns.set_theme(style="darkgrid", font_scale=2)
    sns.kdeplot(data=df2, x=var_x, hue=var_split, common_norm=False, palette=['red', 'green', 'blue', 'orange'], fill=False, ax=axs[0, 1])
    axs[0, 1].set_title(title2)
    axs[0, 1].set_xlabel('Time in seconds')
    axs[0, 1].set_ylabel('Density')
    
    sns.set_theme(style="darkgrid", font_scale=2)
    sns.kdeplot(data=df3, x=var_x, hue=var_split, common_norm=False, palette=['red', 'green', 'blue', 'orange'], fill=False, ax=axs[1, 0])
    axs[1, 0].set_title(title3)
    axs[1, 0].set_xlabel('Time in seconds')
    axs[1, 0].set_ylabel('Density')
    
    sns.set_theme(style="darkgrid", font_scale=2)
    sns.kdeplot(data=df4, x=var_x, hue=var_split, common_norm=False, palette=['red', 'green', 'blue', 'orange'], fill=False, ax=axs[1, 1])
    axs[1, 1].set_title(title4)
    axs[1, 1].set_xlabel('Time in seconds')
    axs[1, 1].set_ylabel('Density')
    
    plt.tight_layout()
    plt.show()

createDensityPlot(osVersions, firstEncrypted, lastEncrypted, firstRansomNote, lastRansomNote, "First encryption", "Last encryption", "First ransom note", "Last ransom note")

techniques = {}
for i in information:
    for k, v in i.items():
        for m in v['mitre']:
            if m not in techniques:
                techniques[m] = {7: 0, 8.1: 0, 10: 0, 11: 0}
            techniques[m][float(k)] += 1


def makeBarChart(techniques):
    max_value = 143
    categories = list(techniques.keys())
    subcategories = list(techniques[categories[0]].keys())
    
    values = {subcat: [(techniques[cat][subcat] / max_value) * 100 for cat in categories] for subcat in subcategories}
    x = np.arange(len(categories))
    _, ax = plt.subplots(figsize=(15, 7))
    bars = []
    for i, subcat in enumerate(subcategories):
        bar = ax.bar(x + i * 0.2, values[subcat], 0.2, label=f'{subcat}')
        bars.append(bar)

    ax.set_xlabel('Techniques')
    ax.set_ylabel('Occurrence in samples (%)')
    ax.set_title('Techniques used per sample in each version')
    ax.set_xticks(x + 0.2 * (len(subcategories) - 1) / 2)
    ax.set_xticklabels(categories)
    ax.legend()

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

makeBarChart(techniques)

incidents = {}
for i in information:
    for version, v in i.items():
        for k, value in v['incidents'].items():
            if k not in incidents:
                incidents[k] = {7: [], 8.1: [], 10: [], 11: []}
            incidents[k][float(version)].append((value['firstSeen'] - i[version]['startTime'])/1000)


def makeDensityChart2(osVersions, incident, values):
    data = []
    for version, values in zip(osVersions, values):
        for value in values:
            data.append({'Windows Version': version, 'Time': value})
    df = pd.DataFrame(data)
    df = df.drop(index=df[(df == 0).any(axis=1)].index)
    var_x = 'Time'
    var_split = 'Windows Version'
    your_data = df
    sns.set_theme(style="darkgrid", font_scale=3)
    plt.figure(figsize=(10, 13))
    sns.kdeplot(data=your_data, x=var_x, hue=var_split, common_norm=False, palette=['red', 'green', 'blue', 'orange'], fill=False)
    plt.title(incident)
    plt.xlabel('Time in seconds')
    plt.ylabel('Density')
    plt.show()


for incident, values in incidents.items():
    values = [values[7], values[8.1], values[10], values[11]]
    makeDensityChart2(osVersions, incident, values)

df = pd.DataFrame(columns=['Windows Version', 'delete', 'write', 'read', 'total'])
counter = 0
for i in information:
    for version, values in i.items():
        # Version, delete, write, read, total
        row = [version, values['counters']['registry']['delete'], values['counters']['registry']['write'], values['counters']['registry']['read'], values['counters']['registry']['total']]
        df.loc[counter] = row
        counter += 1

for osVersion in osVersions:
    print(osVersion)
    subset = df[df['Windows Version'] == osVersion]
    descriptive_stats = subset[['delete', 'write', 'read', 'total']].describe().transpose().round(2)
    print(descriptive_stats)
