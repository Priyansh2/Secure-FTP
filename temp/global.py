import sys
import os
import hashlib
import socket
import time
import re
import glob
import subprocess
import select
import cmd
import rlcompleter
import atexit
import random
import shlex
import tqdm
import stat
from datetime import datetime
from os import name as nm
import humanize


if nm == 'nt':
	from pyreadline import Readline
	readline = Readline()
else:
	import readline

readline.parse_and_bind('tab: complete') # tab completion
histfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), '.pythonhistory') # history file


try:
	readline.read_history_file(histfile)
except IOError:
	print("ok!!")
	pass

atexit.register(readline.write_history_file, histfile)
del histfile, readline, rlcompleter
