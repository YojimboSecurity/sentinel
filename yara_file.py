import os
import yara
import psutil


RULE_FILE = "tools/yara/DoublePulsar.yara"


def directory_tree(startpath):
    for root, dirs, files in os.walk(startpath):
        for file in files:
            yield os.path.join(root, file)

def check_file(file, rule):
    print("Checking file")
    rules = yara.compile(filepath=rule)
    match = rules.match(filepath=file)
    if match:
        print(match)

def check_all_files(rule_file):
    print("[+] checking all files")
    rules = yara.compile(filepath=rule_file)

    for file in directory_tree("C:\\"):
        if file == rule_file:
            #skip rule file
            continue
        match = rules.match(filepath=file)
        if match:
            print("[!] Matched on", file)
            print(match)
            print()

check_all_files(RULE_FILE)

def check_process(process, rule_file):
    print(f"[+] checking for {process}")
    rules = yara.compile(filepath=rule_file)
    for pid in psutil.process_iter():
        if pid.name() == process:
            PID = pid
            print(f"pid for {process} is {pid}")
            break

    match = rules.match(pid=PID.pid)
    print("looking for match")
    if match:
        print(match)
        print(PID)

