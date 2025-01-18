#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from contextlib import contextmanager
import mysql.connector
from mysql.connector import pooling
from threading import Lock

from database_config import MySQLConfig
from decorators import retry_with_backoff, set_session_params, measure_and_log_elapsed_time

logger = logging.getLogger(__name__)


class MySQLConnector:
    _instance = None
    _lock = Lock()

    def __new__(cls, config: MySQLConfig):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MySQLConnector, cls).__new__(cls)
                cls._instance._initialize(config)
        return cls._instance

    def _initialize(self, config: MySQLConfig):
        self.config = config.get_config()
        self.connection_pool = pooling.MySQLConnectionPool(
            pool_name=self.config['pool_name'],
            pool_size=self.config['pool_size'],
            host=self.config['host'],
            port=self.config['port'],
            user=self.config['user'],
            password=self.config['password'],
            database=self.config['database']
        )
        self.connection = None

    @retry_with_backoff()
    def connect(self):
        try:
            self.connection = self.connection_pool.get_connection()
            logger.info("MySQL connection established")
        except mysql.connector.Error as err:
            logger.error(f"Error: {err}")
            self.connection = None

    @contextmanager
    def _get_cursor(self):
        """Context manager to get a cursor from the MySQL connection."""
        if not self.connection:
            self.connect()
        cursor = self.connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    @set_session_params
    @measure_and_log_elapsed_time
    def execute_query(self, query):
        """Executes a query and returns the result."""
        with self._get_cursor() as cursor:
            cursor.execute(query)
            return cursor.fetchall()

    @retry_with_backoff()
    def fetch_data_from_database_and_publish(self, query):
        """Fetches data using a given query."""
        return self.execute_query(query)

    def close(self):
        if self.connection:
            self.connection.close()
            logger.info("MySQL connection closed")
        else:
            logger.info("No active MySQL connection to close")
