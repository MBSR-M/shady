#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json


class KafkaConfig:
    def __init__(self, bootstrap_servers, topic, retries=5, linger_ms=100, username=None, password=None,
                 ssl_check_hostname=None, cafile=None, topic_partitions=None, topic_replication_factor=None,
                 topic_retention_ms=None, flush_timeout_s=None, topic_group_id=None):
        self.__bootstrap_servers = bootstrap_servers
        self.__topic_group_id = topic_group_id
        self.__topic = topic
        self.__retries = retries
        self.__linger_ms = linger_ms
        self.__username = username
        self.__password = password
        self.__ssl_check_hostname = ssl_check_hostname
        self.__cafile = cafile
        self.__topic_partitions = topic_partitions
        self.__topic_replication_factor = topic_replication_factor
        self.__topic_retention_ms = topic_retention_ms
        self.__flush_timeout_s = flush_timeout_s

    def get_config(self):
        config = {
            'bootstrap_servers': self.__bootstrap_servers,
            'topic': self.__topic,
            'retries': self.__retries,
            'linger_ms': self.__linger_ms,
            'value_deserializer': lambda v: json.loads(v.decode('utf-8')),
        }

        if self.__username and self.__password:
            config.update({
                'sasl_mechanism': 'PLAIN',
                'security_protocol': 'SASL_SSL' if self.__ssl_check_hostname or self.__cafile else 'SASL_PLAINTEXT',
                'sasl_plain_username': self.__username,
                'sasl_plain_password': self.__password,
            })

        if self.__cafile:
            config.update({
                'ssl_check_hostname': self.__ssl_check_hostname,
                'ssl_cafile': self.__cafile,
            })

        if self.__topic_partitions:
            config.update({
                'num_partitions': self.__topic_partitions,
            })

        if self.__topic_replication_factor:
            config.update({
                'replication_factor': self.__topic_replication_factor,
            })

        if self.__topic_retention_ms:
            config.update({
                'retention_ms': self.__topic_retention_ms,
            })

        if self.__flush_timeout_s:
            config.update({
                'flush_timeout_ms': int(self.__flush_timeout_s * 1000),
            })

        if self.__topic_group_id:
            config.update({
                'topic_group_id': self.__topic_group_id,
            })

        return config
