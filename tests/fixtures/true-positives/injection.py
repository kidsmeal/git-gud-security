# True-positive fixtures for Python injection patterns

import os, subprocess, yaml, pickle

os.system(user_command)
subprocess.run(cmd, shell=True)
data = yaml.load(user_input)
obj = pickle.loads(untrusted_bytes)
