#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import logging
import os
import random
import time

from datetime import datetime
from kafka import KafkaProducer

from kafka_client import KafkaConfig

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


def generate_random_data():
    """Generate random data to send to Kafka."""
    return {
        'timestamp': datetime.utcnow().isoformat(),
        'sensor_id': random.randint(1, 100),
        'temperature': round(random.uniform(20.0, 30.0), 2),
        'humidity': round(random.uniform(30.0, 70.0), 2),
        'status': random.choice(['OK', 'FAIL', 'WARN'])
    }


def read_server_config(config_file):
    cfg = configparser.ConfigParser()
    cfg.read(config_file)

    for sec, key, envkey, val in (
            ('kafka', 'user', 'KAFKA_USER', ''),
            ('kafka', 'password', 'KAFKA_PASSWORD', ''),
            ('kafka', 'cafile', 'KAFKA_CA_CRT', ''),
            ('kafka', 'bootstrap_servers', 'KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
            ('kafka', 'ssl_check_hostname', 'KAFKA_SSL_CHECK_HOSTNAME', 'true'),
            ('kafka', 'topic', 'KAFKA_TOPIC', 'debug-tool-01'),
            ('kafka', 'topic_replication_factor', 'KAFKA_TOPIC_REPLICATION_FACTOR', '1'),
            ('kafka', 'topic_retention_ms', 'KAFKA_TOPIC_RETENTION_MS', '15552000000'),
            ('kafka', 'flush_timeout_s', 'KAFKA_FLUSH_TIMEOUT_S', '60.0'),
    ):
        if sec not in cfg:
            cfg[sec] = {}
        if key not in cfg[sec]:
            cfg[sec][key] = str(os.environ.get(envkey, val))
    return cfg


def parse_command_line():
    """Parse command line."""
    # build command line parser
    parser = argparse.ArgumentParser(
        description='test-dummy-data',
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable logging a debug level and above',
    )
    parser.add_argument(
        '--log-file',
        default='monitor-rtc-events.log',
        help='Log file',
    )
    parser.add_argument(
        '--config-file',
        default='kafka-conf.conf',
        help='Configuration file',
    )
    return parser.parse_args()


def parse_bool(s):
    return s.lower() in ('true', 't', '1', 'y', 'yes')


def main():
    args = parse_command_line()
    cfg = read_server_config(args.config_file)
    kafka_args = {
        'bootstrap_servers': cfg['kafka']['bootstrap_servers'],
        'ssl_check_hostname': parse_bool(cfg['kafka']['ssl_check_hostname']),
        'username': cfg['kafka']['user'],
        'password': cfg['kafka']['password'],
        'cafile': cfg['kafka']['cafile'],
        'topic': cfg['kafka']['topic'],
        'topic_partitions': int(cfg['kafka'].get('topic_partitions', 1)),
        'topic_replication_factor': int(cfg['kafka']['topic_replication_factor']),
        'topic_retention_ms': int(cfg['kafka']['topic_retention_ms']),
        'flush_timeout_s': float(cfg['kafka']['flush_timeout_s']),
    }
    mq = KafkaConfig(**kafka_args)
    producer = KafkaProducerClient(mq)

    try:
        while True:
            message = generate_random_data()
            print(message)
            producer.send_message(message)
            logger.info(f"Sent message: {message}")
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Shutting down producer.")
    finally:
        producer.close()


if __name__ == "__main__":
    main()
