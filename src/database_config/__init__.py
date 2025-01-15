#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class MySQLConfig:
    def __init__(self, host, port, user, password, database,
                 pool_name='database-pool-01', pool_size=5):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.pool_name = pool_name
        self.pool_size = pool_size

    def get_config(self):
        return {
            'host': self.host,
            'port': self.port,
            'user': self.user,
            'password': self.password,
            'database': self.database,
            'pool_name': self.pool_name,
            'pool_size': self.pool_size
        }
