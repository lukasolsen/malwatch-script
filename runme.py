import os, sys, getopt
import pefile
import analyzers.MalwareClustering.static
from modules.utilities import *


#Use our arguments to specify what they want.
def getArgument():
    if len(sys.argv[0]) < 1:
        print("tf :?")
    print(len(sys.argv[1]))
    if len(sys.argv[1]) < 1:
        print("You need to specify file location.")
        exit()
    else:
        if(os.path.exists(sys.argv[1])):
            return Analyze(sys.argv[1]).run()
            #test()
        else:
            print("File does not exist.")
    return

class Analyze():
    def __init__(self, filepath):
        self.filepath = filepath
        self.api = analyzers.MalwareClustering.static.Static(self.filepath)

    def run(self):
        createNecessarilyItems()
        self.api.run()

def safeStartCheckup():
    if getPythonVersionRunningOn()>(2,7,18):
        modules.logg.Api._error(msg='You need to run this in Python 2.7', shutdown=True, ime=False)

def test():
    modules.logg.Api()._log('Running script')
    modules.logg.Api()._log('Script running in PID: ' + os.getpid())
    safeStartCheckup()
    #checkIfInternetDownFall()

def main(argv):
    inputfile = ''
    outputfile = ''
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print ('test.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('test.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
    print ('Input file is "', inputfile)
    print ('Output file is "', outputfile)



getArgument()




