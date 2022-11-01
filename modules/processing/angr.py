import angr
from clib.malwatch.common.constants import MALWATCH_ROOT
from clib.malwatch.local_settings import ROOT_DESTINATION
from modules.utilities import createFolder, isRunningInLinux, isRunningInWindows

class Api():
    def __init__(self, filepath):
        self.angr = None
        self.filepath = filepath

    def _create_angr_files(self):
        if not self.angr:
            return None
        createFolder(ROOT_DESTINATION, "Angr-Reports")
        f = open(MALWATCH_ROOT + "/submissions/" + "Angr-Reports/angr.txt", 'w+')
        f.write(str(self.angr))
        f.close()

    def run(self):
        try:
            self.angr = angr.Project(self.filepath)
        except:
            return None
        
        self._create_angr_files()