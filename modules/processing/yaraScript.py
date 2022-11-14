try:
    import yara
except ImportError:
    print(
        "Failing when trying to import Yara, Check to see if you have it installed."
    )

try:
    import json
except:
    print("Something went wrong with installing JSON.")
    pass

try:
    import cuckoo
except:
    print(
        "Failed to import Cuckoo python library."
    )
    pass

print("We're using this clas..")
import sys, os

# from signal import signal, SIGPIPE, SIG_DFL

# signal(SIGPIPE,SIG_DFL)

sys.path.insert(1, "/media/sf_Shared/Script/malwatch-script-1/")

from clib.malwatch.common.constants import MALWATCH_ROOT, _current_dir
from clib.malwatch.local_settings import ROOT_DESTINATION
from modules.utilities import changeTerminalName, createFolder


# Use our arguments to specify what they want.
def getArgument():
    if len(sys.argv[0]) < 1:
        print("tf :?")
    print(len(sys.argv[1]))
    if len(sys.argv[1]) < 1:
        print("You need to specify file location.")
        exit()
    else:
        if os.path.exists(sys.argv[1]):
            return Api(sys.argv[1]).run()
            # test()
        else:
            print("File does not exist.")
    return

class yaraApi():
    def __init__(self, filepath):
        self.filepath = filepath

        malware_rules_unc = yara.compile(_current_dir.replace('/clib/malwatch/common', '/data/yara/rules/') + "malware_index.yar")
        self.malware_rules = yara.load(malware_rules_unc)

    def worker1(self):
        
        d = self.malware_rules.match(self.filepath)
        print(d)
        return d

    
    
    def _create(self):
        createFolder(ROOT_DESTINATION, "Yara-Reports")
        f = open(MALWATCH_ROOT + "/submissions/" + "Yara-Reports/yara.json", "w+")
        f.write(str(self.worker1()))
        f.close()
class Api():
    """Main Api"""
    def __init__(self, filepath):
        self.filepath = filepath

    def run(self):
        yaraApi(self.filepath)._create()

getArgument()