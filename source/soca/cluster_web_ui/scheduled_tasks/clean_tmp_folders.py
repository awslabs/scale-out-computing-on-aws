import os
import glob
import logging
logger = logging.getLogger("api_log")

def clean_tmp_folders():
    directories = ["tmp/zip_downloads/*", "tmp/ssh/*"]
    for directory in directories:
        logger.info("Remove files inside " + directory)
        files = glob.glob(directory)
        for f in files:
            os.remove(f)
