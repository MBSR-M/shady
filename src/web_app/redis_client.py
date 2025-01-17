#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import logging
import redis
from dotenv import load_dotenv

load_dotenv()

# Configuration
ENV = os.environ.get("ENVIRONMENT", "LOCAL").upper()
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_USERNAME = os.environ.get("REDIS_USERNAME")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_SSL = os.environ.get("REDIS_SSL", "false").lower() == "true"
REDIS_DB = int(os.environ.get("REDIS_DB", 0))

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Singleton(type):
    """Singleton metaclass to ensure a single instance of the class."""
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class RedisClient(metaclass=Singleton):
    """A robust Redis client with connection pooling and SSL support."""

    def __init__(self):
        try:
            logger.info("Initializing Redis client")
            connection_params = {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "db": REDIS_DB,
            }

            if REDIS_SSL:
                connection_params.update({
                    "connection_class": redis.SSLConnection,
                    "ssl_cert_reqs": None,  # Disable SSL certificate validation (adjust as needed)
                })

            if REDIS_USERNAME and REDIS_PASSWORD:
                connection_params.update({
                    "username": REDIS_USERNAME,
                    "password": REDIS_PASSWORD,
                })

            self.pool = redis.ConnectionPool(**connection_params)
            self._conn = None
            logger.info("Redis client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Redis client: {e}")
            raise

    @property
    def conn(self):
        """Return a Redis connection, creating one if it doesn't exist."""
        if not self._conn:
            self._conn = redis.Redis(connection_pool=self.pool)
            logger.info("Redis connection established")
        return self._conn

    def test_connection(self):
        """Test the Redis connection to ensure it works."""
        try:
            logger.info("Testing Redis connection")
            self.conn.ping()
            logger.info("Redis connection is healthy")
        except redis.ConnectionError as redis_conn_error:
            logger.error(f"Redis connection failed: {redis_conn_error}")
            raise


# Example usage
if __name__ == "__main__":
    try:
        redis_client = RedisClient()
        redis_client.test_connection()
        logger.info("Redis client is ready to use")
    except Exception as e:
        logger.critical(f"Critical error: {e}")
