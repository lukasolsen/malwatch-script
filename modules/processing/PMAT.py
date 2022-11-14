try:
    import lief
except ImportError:
    print(
        "Lief is not installed correctly, see https://lief-project.github.io//doc/latest/installation.html"
    )
    pass

try:
    import yara
except ImportError:
    print(
        "Failing when trying to import Yara, Check to see if you have it installed."
    )

try:
    import magic
except ImportError:
    print(
        "Magic was not installed correctly."
    )
    pass

try:
    import json
except:
    print("Something went wrong with installing JSON.")
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
            return Api(sys.argv[1]).run(sys.argv[1])
            # test()
        else:
            print("File does not exist.")
    return


class liefApi():
    def __init__(self, filepath):
        self.binary = lief.parse(filepath)
        if not self.binary.has_resources:
            print("'{}' has no resources. Abort!".format(self.binary.name), file=sys.stderr)
            sys.exit(1)
        self.root = self.binary.resources
        self.manifest_node = next(iter(filter(lambda e : e.id == lief.PE.RESOURCE_TYPES.MANIFEST, self.root.childs)))
        print(self.manifest_node)

        self.id_node = self.manifest_node.childs[0]
        print(self.id_node)

        self.lang_node = self.id_node.childs[0]
        print(self.lang_node)

        self.manifest = bytes(self.lang_node.content).decode("utf8")

        print(self.manifest)

    def run():
        print("works")

class m():
    def __init__(self, filepath):
        self.filepath = filepath

        self.magic = magic.from_file(self.filepath)

    def returnJson(self):
        d = {
            "magic": self.magic,
        }
        createFolder(ROOT_DESTINATION, "Hashes")
        f = open(MALWATCH_ROOT + "/submissions/" + "Hashes/magic.json", "w+")
        f.write(json.dumps(d, indent=2))

class Api():
    """Main Api"""
    def __init__(self, filepath):
        self.filepath = filepath

    def run(self, filepath):
        # self.angr = angr.Project(self.filepath)
        #liefApi(self.filepath).run()
        m(self.filepath).returnJson()
        # d = AngrInit(self.filepath)._append_To_Result()
        # print(str(d)

changeTerminalName("PMAT")
getArgument()

