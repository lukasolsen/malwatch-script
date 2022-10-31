import os

ALLOWED_HOSTS = ["Linux"]

#When analyzing a malware you will get  a
ENABLE_SAVING_MORE_FILES = True

#Destination of files when analyzing
#If [ENABLE_SAVING_MORE_FILES] is set to False, this will not work.
# To edit use a custom path.
# Default is set to Desktop on Windows
ROOT_DESTINATION_WIN = "Desktop"

# On Linux it's Documents.
ROOT_DESTINATION = 'Documents'