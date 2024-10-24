import subprocess
import os

PATH = "./elfs"

subprocess.call('rm results.csv', shell=True)
for i in os.listdir(PATH):
    file = os.path.join(os.path.join(os.getcwd(), PATH), i)
    print(file)
    subprocess.call(f"python3 ELFMiner.py '{file}'", shell=True)

import subprocess
import datetime

# Generate the current timestamp
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# Construct the new file name with the timestamp
new_file_name = f"dataset_{timestamp}.csv"

# Move the file with the new name
subprocess.call(f"cp results.csv results_feature_engineering/{new_file_name}", shell=True)
subprocess.call(f"mv results.csv system/final.csv", shell=True)
subprocess.call("cd system && make", shell=True)
