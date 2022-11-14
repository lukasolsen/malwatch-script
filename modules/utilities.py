import os, sys
import subprocess
import time
import shutil

from lib.cuckoo.common.constants import CUCKOO_ROOT
from clib.malwatch.local_settings import ROOT_DESTINATION
from clib.malwatch.common.constants import MALWATCH_ROOT,_current_dir

def isFile(file):
    if(os.path.exists(file)):
        return True
    else:
        return False

def isCorrectExtension(file, correctExtension):
    if isFile(file):
        if(os.path.splitext(file)[1]) == correctExtension:
            return True
        else:
            return False

def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])

def getPythonVersionRunningOn():
    return sys.version_info



def createFolder(folder_path, folder_name):
    rotdest = None  
    if folder_path == 'Documents':
        folder_path = MALWATCH_ROOT + "/submissions"
    else:
        folder_path = MALWATCH_ROOT
    
    

    

    if(str(folder_path).endswith('/')):
        if not os.path.exists(folder_path + folder_name):
           os.mkdir(folder_path + folder_name)
        return
    else:
        if not os.path.exists(folder_path +"/" + folder_name):  
            os.mkdir(folder_path + "/" + folder_name)
        return

def getEnvironmentRunningIn():
    if os.name == 'nt':
        return "Windows"
    elif os.name == "posix":
        return "Linux"
    else:
        return "Darwin"

def isRunningInWindows():
    if os.name == 'nt':
        return True
    else:
        return False

def isRunningInLinux():
    if os.name == 'posix':
        return True
    else:
        return False

def isRunningInDarwin():
    if os.name == 'java':
        return True
    else:
        return False

def doCommand(cmd):
    os.system(cmd)

def checkIfInternetDownFall():
    import subprocess
    #Ping GOOGLE DNS Server
    terminal = subprocess.Popen(['gnome-terminal'])
    terminal.stdin.write('ping 8.8.8\n'.encode())
    terminal.stdin.flush()
    terminal.stdin.close()
    terminal.stdout.close()

    #gldns = subprocess.call( ['ping' '8.8.8.8'] )

    

    if gldns.returncode != 0:
        raise Exception ('Invalid Result: '+ {gldns.returncode})
        return False
    else:
        print(gldns.stdout)
        return True


    #os.system('ping 8.8.8.8')

def createNecessarilyItems():
    """Create severe files."""

    if not os.path.exists(CUCKOO_ROOT):
        return None
    
    

    if not os.path.exists(MALWATCH_ROOT):
        os.mkdir(MALWATCH_ROOT)
    
    rotdest = None  
    if ROOT_DESTINATION == 'Documents':
        rotdest = MALWATCH_ROOT + "/submissions"
    else:
        rotdest = MALWATCH_ROOT

    if not os.path.exists(rotdest):
        os.mkdir(rotdest)

    #Create dev files.
    dev_path = MALWATCH_ROOT + "/dev"
    script_folder = dev_path + "/scripts"

    if not os.path.exists(dev_path):
        os.mkdir(dev_path)
    if not os.path.exists(script_folder):
        os.mkdir(script_folder)

    #Move file
    angrFile = _current_dir.replace('clib/malwatch/common', 'modules/processing/') + "angrScript.py"
    pmatFile = _current_dir.replace('clib/malwatch/common', 'modules/processing/') + "PMAT.py"
    yaraFile = _current_dir.replace('clib/malwatch/common', 'modules/processing/') + "yaraScript.py"

    shutil.copy(angrFile, script_folder + "/angrScript.py")
    shutil.copy(pmatFile, script_folder + "/PMAT.py")
    shutil.copy(yaraFile, script_folder + "/yaraScript.py")


def changeTerminalName(name):
    subprocess.Popen("title " + str(name), shell=True)