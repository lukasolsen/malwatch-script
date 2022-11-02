try:
    import angr
    import monkeyhex
except ImportError:
    print(
        "Angr is not installed correctly, see https://docs.angr.io/introductory-errata/install"
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

from clib.malwatch.common.constants import MALWATCH_ROOT
from clib.malwatch.local_settings import ROOT_DESTINATION
from modules.utilities import createFolder, isRunningInLinux, isRunningInWindows


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


class AngrInit:
    def __init__(self, filepath):
        self.filepath = filepath
        self.angr = angr.Project(self.filepath)


        self.loader = self.angr.loader
        self.all_objects = self.loader.all_objects
        self.main_object = self.loader.main_object

        self.main_object__entry = self.main_object.entry
        self.main_object__max_addr = self.main_object.max_addr
        self.main_object__min_addr = self.main_object.min_addr
        self.main_object__segments = self.main_object.segments
        self.main_object__sections = self.main_object.sections
        self.main_object__find_segment_containing_entry = self.main_object.find_segment_containing(self.main_object__entry)
        self.main_object__find_section_containing_entry = self.main_object.find_section_containing(self.main_object__entry)
        #self.main_object__plt_strcmp_ = self.main_object.plt['strcmp']
        #self.main_object__reverse_plt_addr = self.main_object.reverse_plt[self.main_object__plt_strcmp_]
        self.main_object__linked_base = self.main_object.linked_base
        self.main_object__mapped_base = self.main_object.mapped_base



        #self.shared_object = self.loader.shared_object
        self.all_elf_objects = self.loader.all_elf_objects
        self.extern_object = self.loader.extern_object
        self.kernel_object = self.loader.kernel_object
        self.find_object_containing_400 = self.loader.find_object_containing(0x400000)
        self.symbol_strcmp = self.loader.find_symbol('strcmp')


        self.all_content = {}


    def _append_To_Result(self):
        x = {
            "loader": str(self.loader),
            "all_objects": str(self.all_objects),
            "main_object": [
                {"main_object": str(self.main_object)},
                {"entry": str(self.main_object__entry)},
                {"max_addr": str(self.main_object__max_addr)},
                {"min_addr": str(self.main_object__min_addr)},
                {"segments": str(self.main_object__segments)},
                {"sections": str(self.main_object__sections)},
                {"find_segment_containing_entry": str(self.main_object__find_segment_containing_entry)},
                {"find_section_containing_entry": str(self.main_object__find_section_containing_entry)},
                {"linked_base": str(self.main_object__linked_base)},
                {"mapped_base": str(self.main_object__mapped_base)}
            ],
            "all_elf_objects": str(self.all_elf_objects),
            "extern_object": str(self.extern_object),
            "kernel_object": str(self.kernel_object),
            "find_object_containing_400": str(self.find_object_containing_400)
            
        }

        y = json.dumps(x)

        self.all_content["loader"] = self.loader
        self.all_content["all_objects"] = self.all_objects
        self.all_content["main_object"] = self.main_object
        #self.all_content["shared_object"] = self.shared_object
        self.all_content["all_elf_objects"] = self.all_elf_objects
        self.all_content["extern_object"] = self.extern_object
        self.all_content["kernel_object"] = self.kernel_object
        self.all_content["find_object_containing_400"] = self.find_object_containing_400

        return str(json.dumps(x, indent=2))

    def _create_angr_main_dir(self):
        if not self.angr:
            return None

        createFolder(ROOT_DESTINATION, "Angr-Reports")
        f = open(MALWATCH_ROOT + "/submissions/" + "Angr-Reports/angr.txt", "w+")
        f.write(str(self._append_To_Result()))
        f.close()

    def run(self):
        self.angr = angr.Project(self.filepath)
        try:
            self.angr = angr.Project(self.filepath)
        except:
            print("Something went wrong with self.angr instilize.")
            return None

        print(self._append_To_Result())
        self._create_angr_main_dir()


class Api:
    def __init__(self, filepath):
        self.filepath = filepath

    def run(self, filepath):
        # self.angr = angr.Project(self.filepath)
        AngrInit(self.filepath).run()

        # d = AngrInit(self.filepath)._append_To_Result()
        # print(str(d)


getArgument()
