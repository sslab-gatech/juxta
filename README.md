Juxta: Cross-checking Semantic Correctness for File Systems
===========================================================

Environments
------------
- Tested: Ubuntu 14.04
- Requisite
~~~~~~{.sh}
Linux kernel 4.0-rc2
$ cd ..
$ git clone https://github.com/torvalds/linux.git
$ cd linux
$ git checkout v4.0-rc2
$ cp ../juxta/config/config-x86_64-full-fs .
$ make; make clean
$ cd ../juxta
~~~~~~


- How to build
~~~~~{.sh}
Build clang
$  make clang-full  (first time only)
$  make clang       (from the next)
~~~~~


- How to create path databases
~~~~~{.sh}
Merge file system code
$ cd analyzer
$ ./ctrl.py merge_all  (for all file systems)
$ ./ctrl.py merge ext4 (for ext4)

Static analysis of merged file system code
$ ./ctrl.py clang_all  (for all file systems)
$ ./ctrl.py clang ext4 (for ext4)

Create path database
$ ./ctrl.py pickle_all (for all file systems)
$ cd ..
~~~~~


Juxta checkers
--------------
- Return code checker:    analyzer/ckrtn.py
- Side-effect checker:    analyzer/ckstore.py
- Function call checker:  analyzer/ckcall.py
- Path condition checker: analyzer/ckcond.py
- Argument checker:       analyzer/call_flags.py
- Error handling checker: analyzer/ckapi.py
- Lock checker:           analyzer/lock.py
- Spec. generator:        analyzer/spec.py


Authors
-------
- Changwoo Min <changwoo@gatech.edu>
- Sanidhya Kashyap <sanidhya@gatech.edu>
- Byoungyoung Lee <blee@gatech.edu>
- Chengyu Song <csong84@gatech.edu>
- Taesoo Kim <taesoo@gatech.edu>


Publications
------------
- Paper on Juxta
```
Cross-checking Semantic Correctness: The Case of Finding File System Bugs
Changwoo Min, Sanidhya Kashyap, Byoungyoung Lee, Chengyu Song, and Taesoo Kim
SOSP 2015

@inproceedings{min:juxta,
  title        = {{Cross-checking Semantic Correctness: The Case of Finding File System Bugs}},
  author       = {Changwoo Min and Sanidhya Kashyap and Byoungyoung Lee and Chengyu Song and Taesoo Kim},
  booktitle    = {Proceedings of the 25th ACM Symposium on Operating Systems Principles (SOSP)},
  month        = oct,
  year         = 2015,
  address      = {Monterey, CA},
}
```
