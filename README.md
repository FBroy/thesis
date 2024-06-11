# Thesis scripts and data

This repository contains all sorts of scripts used to scrape and work with data related to malware from Malware Bazaar and VX-Underground.

## Installation

To install all the necessary dependencies, just install the Python libraries using `pip install -r requirements.txt` in the root folder.

## Scraping Malware Bazaar & VX-Underground

In order to retrieve the samples from Malware Bazaar and VX-Underground, we first have to scrape the sites in order to see which files they have. Afterwards we download the samples from the scraped data.

**Note**: This will download live malware samples! Make sure you're working on an isolated machine in order to prevent infection and spread on your own network.
This research was conducted on a droplet from Digital Ocean and the samples were executed and ran on a virtual machine on the droplet. We had the approval of Digital Ocean to run malware on their droplet.

### Malware Bazaar

On Malware Bazaar, we use the query `signature:<malware name>` to find all the samples of one family. We then scrape the results and write them to a `.csv` file. The scraping is done by `malwareBazaarScraper.py` and the output is written into a file called `output_<malware name>.csv`. In order to download the actual samples, we use the `malwareBazaarDownloader.py` script. This script reads the `.csv` file which was generated before and downloads every file which is tagged as an executable (`.exe`).

### VX-Underground

On VX-Underground, we use the `vxundergroundLinkFetcher.py` script to retrieve all the file download links. This had to be separated from the downloading script, as the main machine was banned by VX-Underground for scraping too much data. The links can simply be fetched on a normal machine, and then the generated file can be transferred to the machine where the malware will be downloaded to. The link retrieval script generates a file called `<malware name>Links.txt`, which will then be used by the `vxundergroundDownloader.py` script to download the samples.

## Unpacking and renaming the samples

As all the downloaded samples come in archives (to prevent them from executing immediately upon downloading, and to save space), we have to extract them. The `extractor.py` script extracts all the archives using the `infected` password. The Malware Bazaar samples all have the `.exe` extension already, but for the VX-Underground samples we have to add them, which can be done using the `extensionAdder.py` script. Now all the samples should be ready to be analysed.

## Checking for false positives and removing them

Even though the samples are tagged as the specific malware, there can still be false positives. In this research, Windows Defender is used to classify the malware. The first step is to transfer the archive of all the samples to a Windows virtual machine. Upon extracting the archive, Windows Defender will start up and block all of the threats and leave a log behind of which classification it belongs to. Sometimes the log file takes a bit to be updated, so to force an update, a "Quick scan" can be run. Upon waiting for the scan to finish, the logs can be extracted together with the details about each file. The `defenderLogExtractor.py` script takes care of extracting the information from the logs and prints them to the terminal. This can then be pasted into a file or transferred to the main machine. 

Now the false positives need to be manually removed from the file, by deleting the entries in the file which are not classified as the anticipated malware. Which the cleaned up file containing all the true positives, we can now run the `falsePositiveRemover.py` script on our directory containing all the samples and remove all the false positives. After completion of this script, we should now have a folder which contains all the `.exe` files of the true positives as well as their respective archive (`.zip` or `.7z`).

## Extracting information about the samples from Virustotal

In order to get an initial set of information about the collected samples, we use the Virustotal API to fetch the results about these samples. We query 3 endpoints to fetch this data, namely https://www.virustotal.com/api/v3/files/{sha256Hash}, "https://www.virustotal.com/api/v3/files/{sha256Hash}/behaviour_summary" and "https://www.virustotal.com/api/v3/files/{sha256Hash}/behaviour_mitre_trees". The `virustotalAPI.py` script is a Python wrapper which takes care of this. As with the free version of the API, we only have access to 4 lookups per minute, we sleep for 16 seconds after every request in order to make sure we do not go over this quota. Furthermore, we also only have 500 requests per month. The script generates one `.txt` file for every sample with the name `<sha256Hash>.txt` in the `/downloadedInformation` folder.

**NOTE**: For every sample, 3 requests will be made. That this into account when getting the data from VirusTotal.

## Parsing and working with the data from Virustotal

The data which is written to the files in the `/downloadedInformation` folder is in a list format where the elements are in JSON. The `virustotalParser.py` script extracts all the important information inside the parse() function, which can be called from an external script. This information can be further used to find the differences between different samples. All of the fields which are extracted and what they do can be found in the VirusTotal API but also in the comments in the code itself.

## Extracting the results and checking for correlations and differences

The data from `virustotalParser.py` is used in the `resultsExtractor.py` and generates various statistics to analyse the data in more detail.

## Submitting tasks to AnyRun and getting the data

We're using AnyRun's API to automatically submit the samples for an analysis on different version of the Windows operating system. The `apiBulkSubmitter.py` scripts automates the process and submits the files to a Windows 64-bit environment on the specified version, with a timeout of 90 seconds and a clean install of the OS. This way, every analysis is conducted under the exact same circumstances. For every task we submit, we get a taskId, so we store them in a file; 4 taskIds per sample, as we analyse 4 different versions of Windows. 

**Note**: You can only submit a single task at a time and you need to wait until it is finished before sending another one, hence this part can take quite some time depending on the size of the dataset.

Once we have submitted all the samples, we need to retrieve the results from the analysis. The `taskFetcher.py` script parses the previously stored taskIds and retrieves the information in JSON format and stores the result in the respective folder. Now we can parse this information and extract the necessary information with the `versionParser.py` script and finally use the `versionAnalyser.py` script to extract the results we need. The fields which are extracted and analysed can be freely changed or added in the respective script by having a look at the JSON which is retrieved from the analysis.

## Malware samples

The samples can be found in the Dataset folder. The samples are archived by family and the password for each archive is `infected`. WannaCry was split into 2 separate folders, as the combined archive was too big to be uploaded to GitHub. When downloading the samples, they can simply be combined into a single folder once the download and extraction were completed.
