import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
MALWATCH_ROOT = os.path.join(os.path.join(os.path.expanduser('~')), 'Documents/MALWATCH')
MALWATCH_DEV = MALWATCH_ROOT + "/dev"
MALWATCH_SCRIPTS_DIR = MALWATCH_DEV + "/scripts/"

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))