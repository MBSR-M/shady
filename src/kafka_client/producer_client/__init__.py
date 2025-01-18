#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import json
import logging

from kafka import KafkaProducer

from kafka_client import KafkaConfig
from decorators import retry_with_backoff

logger = logging.getLogger(__name__)


class KafkaProducerClient:
    def __init__(self, config: KafkaConfig):
        self.config = config.get_config()
        producer_config = {
            'bootstrap_servers': self.config['bootstrap_servers'],
            'value_serializer': lambda v: json.dumps(v).encode('utf-8'),
            'retries': self.config.get('retries'),
            'linger_ms': self.config.get('linger_ms'),
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
        producer_config.update({k: v for k, v in server_configs.items() if v is not None})
        self.producer = KafkaProducer(**producer_config)

    @retry_with_backoff()
    def send_message(self, message):
        try:
            self.producer.send(self.config['topic'], message)
            self.producer.flush()
            logger.info("Message sent to Kafka")
        except Exception as e:
            logger.error(f"Failed to send message: {e}")

    def close(self):
        if self.producer:
            self.producer.close()
            logger.info("Kafka producer closed")
