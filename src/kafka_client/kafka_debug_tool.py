#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timedelta
from threading import Lock

from kafka import TopicPartition

from debuggingkafka.kafka_client import KafkaConfig
from debuggingkafka.kafka_client.kafka_consumer import KafkaConsumerClient


class ConfigManager:
    """Manages configuration loading from file and environment variables."""

    def __init__(self, config_file):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()

    def load_config(self):
        self.config.read(self.config_file)
        defaults = [
            ('kafka', 'user', 'KAFKA_USER', ''),
            ('kafka', 'password', 'KAFKA_PASSWORD', ''),
            ('kafka', 'cafile', 'KAFKA_CA_CRT', ''),
            ('kafka', 'bootstrap_servers', 'KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
            ('kafka', 'ssl_check_hostname', 'KAFKA_SSL_CHECK_HOSTNAME', 'true'),
            ('kafka', 'topic', 'KAFKA_TOPIC', 'debug-tool-01'),
            ('kafka', 'topic_partitions', 'KAFKA_TOPIC_PARTITIONS', '1'),
            ('kafka', 'topic_replication_factor', 'KAFKA_TOPIC_REPLICATION_FACTOR', '1'),
            ('kafka', 'topic_retention_ms', 'KAFKA_TOPIC_RETENTION_MS', '15552000000'),
            ('kafka', 'flush_timeout_s', 'KAFKA_FLUSH_TIMEOUT_S', '60.0'),
            ('json_file', 'kafka_output_dir', 'kafka_output_dir', 'C:\\test-data\\kafka-output-dir'),
            ('period', 'in_hours', 'in_hours', '24'),
        ]
        for section, key, envkey, default in defaults:
            if section not in self.config:
                self.config[section] = {}
            if key not in self.config[section]:
                self.config[section][key] = os.environ.get(envkey, default)


class ArgumentManager:
    """Manages command-line argument parsing."""

    def __init__(self):
        self.args = self.parse_args()

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(description='Kafka debugger command line parser for Kafka')
        parser.add_argument('--debug', action='store_true', help='Enable debug logging')
        parser.add_argument('--hours', type=int, default=24, help='Offset hours to start dumping Kafka messages')
        parser.add_argument('--log-file', default='kafka-debug.log', help='Log file path')
        parser.add_argument('--debug-kafka', action='store_true', help='Enable Kafka logging')
        parser.add_argument('--log-file-retention-days', type=int, default=180, help='Log file retention in days')
        parser.add_argument('--config-file', default='config.conf', help='Configuration file path')
        return parser.parse_args()


class LoggerManager:
    """Manages logging setup."""

    def __init__(self, log_file, debug, retention_days):
        self.log_file = log_file
        self.debug = debug
        self.retention_days = retention_days
        self.setup_logging()

    def setup_logging(self):
        level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(format="%(asctime)s  %(levelname)-5s  %(message)s", level=level)

        # configure logging to file with retention
        file_handler = logging.handlers.TimedRotatingFileHandler(
            self.log_file, when="midnight", backupCount=self.retention_days
        )
        file_handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-5s  %(message)s"))
        logging.getLogger().addHandler(file_handler)


class KafkaDebug:
    """Handles Kafka message consumption and processing."""

    _instance = None
    _lock = Lock()

    def __new__(cls, kafka_config, period):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(KafkaDebug, cls).__new__(cls)
                cls._instance._initialize(kafka_config, period)
        return cls._instance

    def _initialize(self, kafka_conf: KafkaConfig, period=None):
        self.kafka_conf = kafka_conf
        self.period = period
        self.client = KafkaConsumerClient(kafka_conf)

    def consume_messages(self, process_message):
        """Consume messages from Kafka and process them based on the time period."""
        try:
            # Get the timestamp for the offset (e.g., 24 hours ago or based on self.period)
            period_hours = int(self.period)
            now = datetime.utcnow()
            period_start = now - timedelta(hours=period_hours)
            timestamp_ms = int(period_start.timestamp() * 1000)

            # Seek to the offset corresponding to the timestamp
            for partition in self.client.consumer.partitions_for_topic(self.kafka_conf.get_config().get('topic')):
                topic_partition = TopicPartition(self.kafka_conf.get_config().get('topic'), partition)
                offsets_for_times = self.client.consumer.offsets_for_times({topic_partition: timestamp_ms})
                if offsets_for_times[topic_partition] is not None:
                    self.client.consumer.seek(topic_partition, offsets_for_times[topic_partition].offset)
            # Start consuming messages from the sought offset
            if self.client.consumer is None:
                logging.info('No consumer available for topic %s', self.client.consumer)
                sys.exit(0)
            for message in self.client.consumer:
                metadata = {
                    'topic': message.topic,
                    'partition': message.partition,
                    'offset': message.offset,
                    'timestamp': message.timestamp,
                    'key': message.key,
                    'headers': message.headers,
                }
                process_message(message.value, metadata)
        except AttributeError as a:
            logging.error(f"AttributeError encountered: {a}, no data to consume...")
        except TypeError as typeError:
            logging.error(f"{typeError}, no data to consume...")
        except Exception as e:
            logging.error(f"Failed to consume message: {e}")

    @staticmethod
    def process_messages(messages, metadata):
        """Process and write messages to a JSON file."""
        try:
            response = {'message': messages, 'metadata': metadata}
            print(response)
        except (json.JSONDecodeError, IndexError, KeyError, ValueError) as e:
            logging.error(f"Error processing message: {e}")


class KafkaApp:
    """Main application class that initializes all components and runs the Kafka consumer."""

    def __init__(self):
        # Initialize argument and configuration managers
        self.args = ArgumentManager().args
        self.config = ConfigManager(self.args.config_file).config

        # Initialize logging
        self.logger = LoggerManager(
            log_file=self.args.log_file,
            debug=self.args.debug,
            retention_days=self.args.log_file_retention_days
        )

        # Kafka configuration setup
        kafka_args = {
            'bootstrap_servers': self.config['kafka']['bootstrap_servers'],
            'ssl_check_hostname': self.parse_bool(self.config['kafka']['ssl_check_hostname']),
            'username': self.config['kafka']['user'],
            'password': self.config['kafka']['password'],
            'cafile': self.config['kafka']['cafile'],
            'topic': self.config['kafka']['topic'],
            'topic_partitions': int(self.config['kafka']['topic_partitions']),
            'topic_replication_factor': int(self.config['kafka']['topic_replication_factor']),
            'topic_retention_ms': int(self.config['kafka']['topic_retention_ms']),
            'flush_timeout_s': float(self.config['kafka']['flush_timeout_s']),
        }
        self.kafka_debugger = KafkaDebug(KafkaConfig(**kafka_args), period=self.args.hours)

    def run(self):
        """Start consuming Kafka messages and processing them."""
        self.kafka_debugger.consume_messages(self.kafka_debugger.process_messages)

    @staticmethod
    def parse_bool(value):
        return value.lower() in ('true', 't', '1', 'y', 'yes')


def main():
    KafkaApp().run()


if __name__ == '__main__':
    main()
