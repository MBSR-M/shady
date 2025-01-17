#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging

from kafka import KafkaConsumer

from kafka_client import KafkaConfig

logger = logging.getLogger(__name__)


class KafkaConsumerClient:
    def __init__(self, config: KafkaConfig):
        self.config = config.get_config()
        consumer_config = {
            'bootstrap_servers': self.config['bootstrap_servers'],
            'value_deserializer': lambda x: json.loads(x.decode('utf-8')),
            'auto_offset_reset': 'earliest',
            'enable_auto_commit': False,
            'group_id': self.config['topic_group_id']
        }
        server_configs = {
            'security_protocol': self.config.get('security_protocol'),
            'sasl_mechanism': self.config.get('sasl_mechanism'),
            'sasl_plain_username': self.config.get('sasl_plain_username'),
            'sasl_plain_password': self.config.get('sasl_plain_password'),
            'ssl_check_hostname': self.config.get('ssl_check_hostname'),
            'ssl_cafile': self.config.get('ssl_cafile'),
            'acks': self.config.get('acks'),
            'compression_type': self.config.get('compression_type'),
            'batch_size': self.config.get('batch_size'),
            'buffer_memory': self.config.get('buffer_memory'),
            'max_request_size': self.config.get('max_request_size'),
            'client_id': self.config.get('client_id'),
            'api_version': self.config.get('api_version'),
        }
        consumer_config.update({k: v for k, v in server_configs.items() if v is not None})
        self.consumer = KafkaConsumer(**consumer_config)
        self.consumer.subscribe([self.config['topic']])

    def close(self):
        if self.consumer:
            self.consumer.close()
            logger.info("Kafka consumer closed")
