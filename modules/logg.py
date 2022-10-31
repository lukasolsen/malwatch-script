import logging
from aenum import MultiValueEnum
import datetime
import os
import time

import utilities

class LoggingStatus(MultiValueEnum):
    offline = "Offline", 0
    connected = "Connected", 1
    sending = "Sending", 2
    error = "Error", -1

class Api():
    
    def __init__(self, threshold=40):
        self.started = False
        self.error_Encountered = 0
        self.threshold = threshold
        self.loggingStatus = LoggingStatus.offline
        self.logger = logging.getLogger("Malwatch MAAT")

        self.logToFile = logging

        
        
        
        

    def connect(self):
        if self.loggingStatus == LoggingStatus.error:
            return None
    
        
        date = datetime.datetime.now()
        curr_date = date.strftime('%d_%m_%Y')
        self.logToFile.basicConfig(filename='malwatch---' + curr_date + '.log')
        self.logToFile.Formatter('[%(levelname)s: %(asctime)s] %(name)s: %(message)s', datefmt='%Y-%d-%m %I:%M:%S %p')
        
        self.logger.setLevel(logging.DEBUG)
        self.logToFile.addLevelName(logging.ERROR, 'Error')
        self.logToFile.addLevelName(logging.CRITICAL, 'Critical')
        self.logToFile.addLevelName(logging.DEBUG, 'Debug')
        self.logToFile.addLevelName(logging.INFO, 'Info')
        self.logToFile.addLevelName(logging.ERROR, 'Error')

        self.consoleHandler = logging.StreamHandler()

        self.consoleHandler.setLevel(logging.DEBUG)

        formatter = logging.Formatter('[%(levelname)s: %(asctime)s] %(name)s: %(message)s', datefmt='%Y-%d-%m %I:%M:%S %p')
        self.consoleHandler.setFormatter(formatter)

        self.logger.addHandler(self.consoleHandler)

        self.started = True
        self.loggingStatus = LoggingStatus.connected

    def _log(self, msg):
        self.loggingStatus = LoggingStatus.sending
        self.logger.info(str(msg))
        self.loggingStatus = LoggingStatus.connected

    def _debug(self, msg):
        self.loggingStatus = LoggingStatus.sending
        self.logger.info(str(msg))
        self.loggingStatus = LoggingStatus.connected

    def _error(self, msg, shutdown, ime):
        self.loggingStatus = LoggingStatus.sending
        self.logger.error(str(msg))

        if shutdown:
            if ime:
                self.logger.error('Something occurred, waiting for server to respond.')
                self.logger.debug('Checking if Script have access to internet..')
                print(utilities.checkIfInternetDownFall())
                self.logger.critical("SHUTTING DOWN...")
                self.logger.critical("SHUTTING DOWN...")
                self.logger.critical("SHUTTING DOWN...")
                

                self.logToFile.error('Connection lost: ' + datetime.datetime.now())
                self.logToFile.error('Script ended with 0 :: PID [' + os.getpid() + ']')
                self.loggingStatus = LoggingStatus.offline
                exit()
            else:
                self.logger.critical("SHUTTING DOWN IN 5 SECONDS.")
                self.logger.error("Shutting down..")
            

Api().connect()
Api()._log('testing..')
Api()._error('This is just a test..', shutdown=True, ime=True)