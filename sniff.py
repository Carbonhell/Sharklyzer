import sys
import threading
from datetime import datetime

import pyshark
from selenium import webdriver

try:
    sites = sys.argv[1]
    timeout = sys.argv[2]
except Exception:
    print('Usage: python sniff.py textfile minutes')
    print('\ttextfile: filename of a file containing websites, one per line (es. websites.txt)')
    print('\tminutes: timeout in minutes (es. 5)')
    sys.exit("Error: Missing arguments")


def start_sniff(t):
    cur_datetime = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    output_filename = t + '_' + cur_datetime + '.cap'
    capture = pyshark.LiveCapture(interface='Wi-Fi', output_file='sniff_results/' + output_filename)  # netsh wlan show interfaces
    capture.sniff(timeout=60 * int(t))  # seconds
    capture.close()


def open_websites(websites, driver):
    for tab, site in enumerate(websites, 1):
        driver.get(site)
        driver.execute_script("window.open('');")
        driver.switch_to.window(driver.window_handles[tab])


websites = [x for x in open(sites, 'r').read().split('\n')]
driver = webdriver.Chrome('./bin/chromedriver.exe')
print("Current time: " + str(datetime.now()))
print("Starting live-capture...")
sniff_thread = threading.Thread(target=start_sniff, args=(timeout,))
sniff_thread.start()
open_websites(websites, driver)
sniff_thread.join()  # Wait until sniffing ends
driver.quit()
print("Live-capture completed.")
