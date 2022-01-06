import logging


logger = logging.getLogger('netscanlog')

def init_log(verbose):
    loggingLevel = (logging.DEBUG if verbose else logging.INFO)

    logger.setLevel(loggingLevel)

    consoleLogger = logging.StreamHandler()
    consoleLogger.setLevel(loggingLevel)
    logger.addHandler(consoleLogger)