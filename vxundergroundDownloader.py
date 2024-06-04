from tqdm import tqdm
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options


malwareName = "Ryuk"
options = Options()
options.set_preference("browser.download.folderList", 2)
options.set_preference("browser.download.manager.showWhenStarting", False)
options.set_preference("browser.download.dir", f"/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/vxunderground/")

geckoPath = "/snap/bin/geckodriver"
browserService = webdriver.FirefoxService(executable_path=geckoPath)

browser = webdriver.Firefox(options=options, service=browserService)
browser.set_page_load_timeout(1)
with open(f"/home/frank/Documents/thesisScripts/MalwareSamples/{malwareName}/{malwareName}Links.txt", 'r') as f:
    links = f.readlines()
    for link in tqdm(links):
        try:
            browser.get(link.replace("\n", ''))
        except:
            continue
browser.close()