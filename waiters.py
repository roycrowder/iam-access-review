# -*- coding: utf-8 -*-
import logging

# Initialize logging
logger = logging.getLogger(__name__)

# This constant is used to define the name of the last
# access details waiter. Consistency is required to use
# of the waiter in other places in the code.
LAST_ACCESS_DETAILS_WAITER_NAME = 'LastAccessDetailsJob'

def last_access_details_waiter_config(delay, max_attempts):
    """Builds the configuration for the last access details AWS IAM custom waiter.

    Args:
        delay (int): defines the amount of seconds to wait before checking
                if the report ran.
        max_attempts (int): defines the maximum number of times to check if the
            report finished.

    Returns:
        dict: configuration of the last access details IAM waiter.
    """
    logger.info('Configuring last access details waiter. Delay: %s, Max Attempts: %s.' % (delay, max_attempts))
    config = {
        'version': 2,
        'waiters': {
            LAST_ACCESS_DETAILS_WAITER_NAME: {
                'operation': 'get_service_last_accessed_details',
                'delay': delay,
                'maxAttempts': max_attempts,
                'acceptors': [
                    {
                        'matcher': 'path',
                        'expected': 'COMPLETED',
                        'argument': 'JobStatus',
                        'state': 'success'
                    },
                    {
                        'matcher': 'path',
                        'expected': 'IN_PROGRESS',
                        'argument': 'JobStatus',
                        'state': 'retry'
                    },
                    {
                        'matcher': 'path',
                        'expected': 'FAILED',
                        'argument': 'JobStatus',
                        'state': 'failure'
                    }
                ]
            }
        }
    }

    logger.debug(config)

    return config