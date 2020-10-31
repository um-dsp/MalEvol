# -*- coding: utf-8 -*-
"""
Created on Tue Jul  7 20:53:12 2020

@author: abder
"""

#!/usr/bin/env python

# 
# XOR Bruteforcer: tries all the possible values for a XOR key looking for a pattern in the output. A single key can be specified too.
#
# http://eternal-todo.com
# Jose Miguel Esparza
#

from itertools import cycle, izip
import sys,os,re


def process (ss, key):
    key = cycle(key)
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(ss, key))

found = False
param = ""
xorKey = ""
successfullKeys = []
usage = "Usage: "  + sys.argv[0] + ''' -k xor_key file [search_pattern]

Arguments:

    file: the source file to be xored.
    search_pattern: pattern that must be found in the xored result.

Options:

    -k xor_key: key used in the XOR function (00-ff). If not specified, all the possible values will be tested (bruteforcing).
'''

print sys.argv[1]
if len(sys.argv) == 2 or len(sys.argv) == 3:
   file = sys.argv[1]
   if len(sys.argv) == 3:
      param = sys.argv[2]
elif len(sys.argv) == 4 or len(sys.argv) == 5:
   if sys.argv[1] != "-k":
      sys.exit(usage)
   xorKey = sys.argv[2]
   if not re.match("[0-9a-f]{1,2}",xorKey):
      sys.exit(usage)
   xorKey = int(xorKey,16)
   file = sys.argv[3]
   if len(sys.argv) == 5:
      param = sys.argv[4]
else:
    sys.exit(usage)

if not os.path.exists(file):
   sys.exit('Error: the file does not exist!!')

content = open(file,"r").read()
if xorKey != "":
   decValues = [xorKey]
else:
   decValues = range(256)

for i in decValues:
   key = chr(i)
   deciphered = process(content, key)
   if param == "":
      print "["+hex(i).upper()+"]"
      print deciphered
      print "[/"+hex(i).upper()+"]"
   elif re.findall(param,deciphered,re.IGNORECASE) != []:
      found = True
      successfullKeys.append(hex(i).upper())
      print "["+hex(i).upper()+"]"
      print deciphered
      print "[/"+hex(i).upper()+"]"

if param != "":
   if not found:
      sys.exit("Warning: Pattern not found!!")
   else:
      sys.exit("Pattern found using the following keys: "+str(successfullKeys))
