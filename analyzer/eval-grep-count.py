# SPDX-License-Identifier: MIT
import os
import subprocess
import multiprocessing as mp

ROOT  = os.path.abspath(os.path.dirname(__file__))
#PKL_BASE_DIR = "/data/fss-data/out-2015-03-19"
PKL_BASE_DIR = "/tmp/fss-output-eYOG/linux-3.17/fs"

def run(full_fs_dir, pattern):
    cmd_str = "./_eval-grep-count.sh %s %s" % (full_fs_dir, pattern)

    p = subprocess.Popen(["/bin/bash", "-c", cmd_str, full_fs_dir, pattern],
                         stdout=subprocess.PIPE)
    comm = p.communicate()
    num = int(comm[0].strip())
    return num
    
def count(fs_name, full_fs_dir):
    num_path = run(full_fs_dir, '"^@FUNCTION:"')    
    num_cond = run(full_fs_dir, '"^@CONDITION"')
    num_conj = run(full_fs_dir, '"^@CONDITION: (E #"')
    print "%s\t %d\t %d\t %d" % (fs_name, num_path, num_cond-num_conj, num_conj)
    return

if __name__ == "__main__":
    for fs_name in os.listdir(PKL_BASE_DIR):
        full_fs_dir = os.path.join(PKL_BASE_DIR, fs_name)
        if not os.path.isdir(full_fs_dir):
            continue
        count(fs_name, full_fs_dir)

