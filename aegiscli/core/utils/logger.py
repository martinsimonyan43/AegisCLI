import os
from datetime import datetime
import sys
LOG_DIR = os.path.expanduser("~/.aegiscli/logs")
os.makedirs(LOG_DIR, exist_ok=True)

file = None
logging = False

def start_log():
    global file, logging
    logging = True
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(LOG_DIR, f"aegiscli_{ts}.log")

    file = open(path, "w", encoding="utf-8")
    file.write(f"[LOG START] {datetime.now()} \n")
    return path        

def log(text):
    global file, logging
    print(text)
    if logging == True:
        file.write(text + "\n")


def stop_log():
    global file, logging
    if file:
        file.close()
    logging = False
