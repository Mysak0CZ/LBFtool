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
if True:
    import struct
    import sys
    import os
    import xml.etree.ElementTree as ET
    from hashlib import sha256

try:
    from Crypto.Cipher import AES
except:
    print("Could not load Crypto library, please install pycryptodome package (python -m pip install pycryptodome)")
    exit(1)

if len(sys.argv) != 2:
    print("Usage: "+sys.argv[0]+" <file.lbf>")
    exit(1)

FILE_NAME = sys.argv[1]

# Data obtained through reverse-engineering
ENC_KEY = b"cd562f61-5399-3978-ac76-7c54b0508010"
# AES/ECB/PKCS5Padding + SHA256


def unpad(s): return s[0:-s[-1]]


if os.path.exists(EXPORT_DIR):
    print("Export folder already exists, please remove it before running script")
    exit(1)

if not FILE_NAME.endswith(".lbf"):
    print(".lbf file expected")
    exit(1)

usedList = []

dataNames = [FILE_NAME]
dataFiles = [open(FILE_NAME, "rb")]
dataFiles[0].seek(0, 2)
datalen = dataFiles[0].tell()
dataSizes = [datalen]


def checkIsNull(data):
    for i in data:
        if i != 0:
            return False
    return True


def getDataIndex(start):
    global datalen, dataSizes
    if start > datalen:
        raise Exception("Data starts outside of loaded files: " +
                        str(start)+"/"+str(datalen))
    for i in range(len(dataSizes)):
        if start < dataSizes[i]:
            return i
    assert False


def readData(start, length):
    global dataFiles, dataSizes, usedList
    filei = getDataIndex(start)
    fileoffset = start if filei == 0 else start-dataSizes[filei-1]
    file = dataFiles[filei]
    if start+length > dataSizes[filei]:
        raise Exception("Cross-file data")
    file.seek(fileoffset)
    usedList.append((start, length))
    res = file.read(length)
    assert len(res) == length
    return res


# Just write the data
def exportData(name, offset, length):
    if length == 0:
        return
    data = readData(offset, length)
    name = EXPORT_DIR + name
    if checkIsNull(data):
        print("Skiping NULL data: "+name)
        return
    if not os.path.isdir(os.path.dirname(name)):
        os.makedirs(os.path.dirname(name))
    if os.path.exists(name):
        raise Exception("Target already exists: "+str(name))
    with open(name, "wb") as f:
        f.write(data)


# Extracted encryption function
def decrypt(data):
    global ENC_KEY
    cypher = AES.new(sha256(ENC_KEY).digest(), AES.MODE_ECB)
    return unpad(cypher.decrypt(data))


# Get size of header
def getBackupInfoSize(isNew):
    global datalen
    pos = 1 if isNew else datalen - 5
    backupInfoSize = struct.unpack("!L", readData(pos, 4))[0]
    if backupInfoSize < 1 or backupInfoSize > 10485760:
        raise Exception("Invalid header length.")
    return backupInfoSize


# Get, decrypt and parse header
def readHeader(isNew):
    global datalen
    print("    Reading header " + ('(new)' if isNew else ''))
    pos = 5 if isNew else datalen - 13
    r4 = struct.unpack("!Q", readData(pos, 8))[0]
    print("[*] Header start offset: " + str(r4))
    size = getBackupInfoSize(isNew)
    print("[*] Header length: " + str(size))
    res = readData(r4, size)
    assert len(res) == size
    res2 = decrypt(res)
    name = (EXPORT_DIR + "header-new.xml") if isNew else (EXPORT_DIR + "header.xml")
    if not os.path.isdir(os.path.dirname(name)):
        os.makedirs(os.path.dirname(name))
    with open(name, "wb") as f:
        f.write(res2)
    print("[+] Header read OK")
    return ET.fromstring(res2.decode("utf-8", errors="ignore"))


def getAttrByName(name):
    global cmnHdr
    for el in cmnHdr.findall("Attr"):
        if el.get("Name") == name:
            return el
    return None


def getCGPath(name):
    sp = name.split("_CG_")
    job = sp[0]
    index = int(sp[1])
    attr = getAttrByName("KEY_MEDIA_JOB_"+job+"KEY_MEDIA_TYPE_0")
    assert attr != None
    path = attr.text.split("@@")[index]
    return path.replace("@", "")


# Main
if __name__ == "__main__":
    print("[+] Backup size: " + str(datalen))
    print("    Parsing...")
    isLocked = readData(datalen-1, 1) != b"\x00"
    if isLocked:
        password = readData(datalen-33, 20)
        print("[+] The file is locked and the password hash (sha1) is: "+password.hex())
    else:
        print("[+] File is not locked")
    root = readHeader(FORCE_NEW_HEADER)
    cmnHdr = root.find("Common")
    if cmnHdr is None:
        raise Exception("Common header not found")

    subFileSize = getAttrByName("SubFileSize")
    if subFileSize != None and int(subFileSize.text) > 1:
        print("[*] Backup is multipart, loading other files...")
        dataFiles[0].close()
        dataFiles = []
        dataNames = []
        dataSizes = []
        count = int(subFileSize.text)-1
        err = False
        for i in range(count):
            name = FILE_NAME+str(i)
            if not os.path.exists(name):
                print("[-] Failed to load file: "+name)
                err = True
            dataNames.append(name)
        if err:
            print("    Please make sure all files are in the same directory as main file")
            print("Cannot continue")
            exit(2)
        dataNames.append(FILE_NAME)
        datalen = 0
        for name in dataNames:
            file = open(name, "rb")
            file.seek(0, 2)
            datalen += file.tell()
            dataFiles.append(file)
            dataSizes.append(datalen)
        print("[+] Opened "+str(count+1) +
              " backup files, total size: "+str(datalen))
        # The old header and password are not missing
        shift = dataSizes[-2]
        for i in range(len(usedList)):
            usedList[i] = (usedList[i][0]+shift, usedList[i][1])

    if not FORCE_NEW_HEADER and not FORCE_OLD_HEADER:
        isNew = cmnHdr.find("IsNew")
        isNew = isNew is not None and isNew.text == "True"
        if isNew:
            root = readHeader(True)
            cmnHdr = root.find("Common")
            if cmnHdr is None:
                raise Exception("Common header not found")
    print("    Extracting data...")
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
                targetName = elem.get("Category") + "-" + \
                    elem.get("FileName", "")
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
    pos = 1
    for item in sorted(usedList, key=lambda x: x[0]):
        if item[0] > pos:
            ln = item[0]-pos
            exportData("missed/"+str(pos)+"-"+str(item[0]-1)+".dat", pos, ln)
        elif item[0] < pos:
            print("Overlap!: pos: "+str(pos)+" start: " +
                  str(item[0])+" len: "+str(item[1]))
            continue
        pos = item[0]+item[1]
    if pos < datalen:
        ln = datalen-pos
        exportData("missed/"+str(pos)+"-"+str(datalen-14)+".dat", pos, ln)
    print("Done!")
