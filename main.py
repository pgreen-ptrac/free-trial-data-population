import yaml

import settings
import utils.log_handler as logger
log = logger.log
from utils.auth_handler import Auth
import utils.input_utils as input


if __name__ == '__main__':
    for i in settings.script_info:
        print(i)

    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)


    """
    Config File
    """
    log.info(args.get('instance_url'))


    auth = Auth(args)
    auth.handle_authentication()
