#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import functools
import logging
import sys
import time
from functools import wraps

logger = logging.getLogger(__name__)


def retry_with_backoff(max_retries=5, delay=5, backoff=1, exceptions=(Exception,)):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    retries += 1
                    if retries == max_retries:
                        logger.error(f"Error: {e}, reached max retries ({max_retries}). Exiting with status 0.")
                        sys.exit(0)
                    logger.error(f"Error: {e}, retrying in {current_delay} seconds... ({retries}/{max_retries})")
                    time.sleep(current_delay)
                    current_delay *= backoff

        return wrapper

    return decorator


# Example decorator implementation to handle instance methods
def retry_with_backoff_func(retries=3, delay=1, backoff=2):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal delay
            attempt = 0
            while attempt < retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Attempt {attempt + 1} failed with exception: {e}")
                    if attempt >= retries - 1:
                        logger.error("Max retries reached. Failing.")
                        raise
                    attempt += 1
                    time.sleep(delay)
                    logger.info(f"Retrying after {delay} seconds...")
                    delay *= backoff
        return wrapper
    return decorator


def measure_and_log_elapsed_time(f):
    def func(*args, **kwargs):
        start_time = time.monotonic()
        result = f(*args, **kwargs)
        end_time = time.monotonic()
        elapsed_time = end_time - start_time
        logger.debug('%s() took %.3fs', f.__name__, elapsed_time)
        return result

    return func


def set_session_params(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self._get_cursor() as cursor:
            cursor.execute("SET @@SESSION.time_zone = '+0:00'")
            cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            cursor.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT')
            result = func(self, *args, **kwargs)
        return result

    return wrapper
