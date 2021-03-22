import os
import stat
import logging
logger = logging.getLogger("scheduled_tasks")


def validate_db_permissions():
    # Ensure db.sqlite permissions are always 600
    logger.info(f"validate_db_permissions")
    db_sqlite = os.path.abspath(os.path.dirname(__file__) + "/../db.sqlite")
    check_stat = os.stat(db_sqlite)
    oct_perm = oct(check_stat.st_mode)
    logger.info(f"validate_db_permissions: Detected permission {oct_perm} for {db_sqlite} with last 3 digits {oct_perm[-3:]}")
    if oct_perm[-3:] != '600':
        logger.info("validate_db_permissions: Updated permission back to 600")
        os.chmod(db_sqlite, stat.S_IWUSR + stat.S_IRUSR)