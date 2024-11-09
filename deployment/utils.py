import logging
import time
from configs import *

logger = logging.getLogger('vm_deploy_logger')

# Run the task and log infos and errors
# Exit if task failed
def run_task(task_name, task, *args):
    logger.info(task_name)
    try:
        ret = task(*args)
    except Exception as e:
        logger.error('{} failed: {}'.format(task_name, e))
        raise e
    else:
        logger.info('{} done'.format(task_name))
        return ret

# Retry the task for at most max_n_try times
# Sleep for retry_interval seconds between two tries
def repeat_try_task(task_name, max_n_try, retry_interval, task, *args):
    logger.info(task_name)
    n_try = 0
    while True:
        try:
            ret = task(*args)
        except Exception as e:
            logger.error('Try {}, {} failed: {}'.format(n_try, task_name, e))
            n_try += 1
            if n_try == max_n_try:
                raise e
            time.sleep(retry_interval)
        else:
            logger.info('{} done'.format(task_name))
            return ret

# Run the command and log outputs
# Wait until the command is done
def exec_command_sync_ignore_err(ssh, cmd):
    _, stdout, _ = ssh.exec_command('{} && echo done'.format(cmd))
    logger.info(stdout.read().decode('utf-8'))

# Run the command and log outputs
# Wait until the command is done
def exec_command_sync(ssh, cmd):
    _, stdout, stderr = ssh.exec_command('{} && echo done'.format(cmd))
    logger.info(stdout.read().decode('utf-8'))
    logger.error(stderr.read().decode('utf-8'))

def get_logger(log_file):
    logger = logging.getLogger(log_file)
    
    file_handler = logging.FileHandler(log_file, 'w', encoding='utf-8')
    fmt = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    logger.setLevel(logging.INFO)

    return logger


if __name__ == '__main__':
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S %p"
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)
