#!/usr/bin/env python3
# -*- coding: utf-8 -*-

### Settings ###

# Attemp to reconstruct media paths, set to False if you get errors while extracting
TRY_PATH_RECONSTRUCT = True
# If one of the headers is corrupted, these can help
FORCE_NEW_HEADER = False
FORCE_OLD_HEADER = False
# Name of the output directory
EXPORT_DIR = "./export/"

### You shoudln't change anything below ###

import os, sys, struct
from hashlib import sha256
import xml.etree.ElementTree as ET
try:
    from Crypto.Cipher import AES
except:
    print("Could not load Crypto library, please install pycrypto package (python -m pip install pycrypto)")
    exit(1)

if len(sys.argv) != 2:
    print("Usage: "+sys.argv[0]+" <file.lbf>")
    exit(1)

FILE_NAME = sys.argv[1]

# Data obtained through reverse-engineering
ENC_KEY = b"cd562f61-5399-3978-ac76-7c54b0508010"
# AES/ECB/PKCS5Padding + SHA256

unpad = lambda s: s[0:-s[-1]]

data = open(FILE_NAME, "rb")
data.seek(0, 2)
datalen = data.tell()

if os.path.exists(EXPORT_DIR):
    print("Export folder already exists, please remove it before running script")
    exit(1)

usedList = []

def checkIsNull(offset, length):
    global data
    data.seek(offset)
    for _ in range(length):
        if data.read(1) != b"\x00":
            return False
    return True

# Just write the data
def exportData(name, offset, length):
    global usedList, data, datalen
    if length == 0:
        return
    if offset+length > datalen:
        raise Exception("Data too large; end: "+str(offset+length))
    name = EXPORT_DIR + name
    usedList.append((offset, length))
    if checkIsNull(offset, length):
        print("Skiping NULL data: "+name)
        return
    if not os.path.isdir(os.path.dirname(name)):
        os.makedirs(os.path.dirname(name))
    if os.path.exists(name):
        raise Exception("Target already exists: "+str(name))
    with open(name, "wb") as f:
        data.seek(offset)
        f.write(data.read(length))

# Extracted encryption function
def decrypt(data):
    global ENC_KEY
    cypher = AES.new(sha256(ENC_KEY).digest(), AES.MODE_ECB)
    return unpad(cypher.decrypt(data))

# Get size of header
def getBackupInfoSize(isNew):
    global data, datalen
    pos = 1 if isNew else datalen - 5
    data.seek(pos)
    backupInfoSize = struct.unpack("!L", data.read(4))[0]
    if backupInfoSize < 1 or backupInfoSize > 10485760:
        raise Exception("Invalid header length.")
    return backupInfoSize

# Get, decrypt and parse header
def readHeader(isNew):
    global data, datalen, usedList
    print("    Reading header " + ('(new)' if isNew else ''))
    pos = 5 if isNew else datalen - 13
    data.seek(pos)
    r4 = struct.unpack("!Q", data.read(8))[0]
    print("[*] Header start offset: " + str(r4))
    size = getBackupInfoSize(isNew)
    print("[*] Header length: " + str(size))
    data.seek(r4)
    res = data.read(size)
    assert len(res) == size
    usedList.append((r4, size))
    res2 = decrypt(res)
    name = (EXPORT_DIR + "header-new.xml") if isNew else (EXPORT_DIR + "header.xml")
    if not os.path.isdir(os.path.dirname(name)):
        os.makedirs(os.path.dirname(name))
    with open(name, "wb") as f:
        f.write(res2)
    print("[+] Header read OK")
    return ET.fromstring(res2.decode("utf-8", errors="ignore"))

# Main
print("[+] Backup size: " + str(datalen))
print("    Parsing...")
root = readHeader(FORCE_NEW_HEADER)
cmnHdr = root.find("Common")
if cmnHdr is None:
    raise Exception("Common header not found")
if not FORCE_NEW_HEADER and not FORCE_OLD_HEADER:
    isNew = cmnHdr.find("IsNew")
    isNew = isNew is not None and isNew.text == "True"
    if isNew:
        root = readHeader(True)
        cmnHdr = root.find("Common")
        if cmnHdr is None:
            raise Exception("Common header not found")
print("    Extracting data...")
data.seek(datalen-1)
isLocked = data.read(1) != b"\x00"
if isLocked:
    data.seek(datalen-33)
    password = data.read(20)
    print("[+] The file is locked and the password hash (sha1) is: "+password.hex())
else:
    print("[+] File is not locked")

def getAttrByName(name):
    global cmnHdr
    for el in cmnHdr.findall("Attr"):
        if el.get("Name") == name:
            return el
    raise Exception("Attr not found: "+name)

def getCGPath(name):
    sp = name.split("_CG_")
    job = sp[0]
    index = int(sp[1])
    path = getAttrByName("KEY_MEDIA_JOB_"+job+"KEY_MEDIA_TYPE_0").text.split("@@")[index]
    return path.replace("@", "")

items = root.findall("BackupItem")
for i in range(len(items)):
    try:
        print("  "+str(i+1)+"/"+str(len(items))+"  ", end="\r")
        elem = items[i]
        if elem.get("Category") == "APPLICATION":
            for app in elem.findall("APPLICATION"):
                targetName = "app/" + app.get("FileName", app.get("Name"))
                start = int(app.get("StartOffset"))
                size = int(app.get("DataSize"))
                exportData(targetName, start, size)
        else:
            targetName = elem.get("Category") + "-" + elem.get("FileName", "")
            if targetName[-1] == "-":
                targetName = targetName[:-1]
            if "_CG_" in targetName:
                if TRY_PATH_RECONSTRUCT:
                    targetName = "misc"+getCGPath(elem.get("Category"))
                else:
                    targetName = "misc/"+targetName
            else:
                targetName = "data/" + targetName
            start = int(elem.get("StartOffset"))
            size = int(elem.get("DataSize"))
            exportData(targetName, start, size)
    except Exception as e:
        print("Error extracting '"+elem.get("Category")+"': ", e)
print("\nLooking for missed data...")
if FORCE_NEW_HEADER:
    try:
        readHeader(False)
    except:
        pass
if FORCE_OLD_HEADER:
    try:
        readHeader(True)
    except:
        pass
pos = 13
for item in sorted(usedList, key=lambda x: x[0]):
    if item[0] > pos:
        ln = item[0]-pos
        exportData("missed/"+str(pos)+"-"+str(item[0]-1)+".dat", pos, ln)
    elif item[0] < pos:
        print("Overlap!: pos: "+str(pos)+" start: "+str(item[0]))
    pos = item[0]+item[1]
if pos < datalen-13:
    ln = datalen-13-pos
    exportData("missed/"+str(pos)+"-"+str(datalen-14)+".dat", pos, ln)
print("Done!")
