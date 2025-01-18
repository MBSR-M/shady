#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def sanitize_input(raw: str) -> str:
    """Sanitize input to prevent injection attacks."""
    if not isinstance(raw, str):
        logger.warning("Input is not a string. Converting to string.")
        raw = str(raw)

    CLEAR = ""
    sanitized = raw.replace("#", CLEAR).replace("--", CLEAR).replace(";", CLEAR)
    logger.info("Input sanitized.")
    return sanitized


ones = {
    0: '', 1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five', 6: 'six',
    7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten', 11: 'eleven', 12: 'twelve',
    13: 'thirteen', 14: 'fourteen', 15: 'fifteen', 16: 'sixteen',
    17: 'seventeen', 18: 'eighteen', 19: 'nineteen'
}
tens = {
    2: 'twenty', 3: 'thirty', 4: 'forty', 5: 'fifty', 6: 'sixty',
    7: 'seventy', 8: 'eighty', 9: 'ninety'
}
illions = {
    1: 'thousand', 2: 'million', 3: 'billion', 4: 'trillion', 5: 'quadrillion',
    6: 'quintillion', 7: 'sextillion', 8: 'septillion', 9: 'octillion',
    10: 'nonillion', 11: 'decillion'
}


def say_number(i):
    """Convert a number into its English representation."""
    if not isinstance(i, int):
        logger.error("Input must be an integer.")
        raise ValueError("Input must be an integer.")

    logger.info(f"Converting number: {i}")
    if i < 0:
        return _join('negative', _say_number_pos(-i))
    return 'zero' if i == 0 else _say_number_pos(i)


def _say_number_pos(i):
    """Handle the positive portion of number conversion."""
    if i < 20:
        return ones[i]
    if i < 100:
        return _join(tens[i // 10], ones[i % 10])
    if i < 1000:
        return _divide(i, 100, 'hundred')
    for illions_number, illions_name in illions.items():
        if i < 1000 ** (illions_number + 1):
            break
    return _divide(i, 1000 ** illions_number, illions_name)


def _divide(dividend, divisor, magnitude):
    """Divide and format the number based on magnitude."""
    logger.debug(f"Dividing {dividend} by {divisor} for magnitude {magnitude}")
    return _join(
        _say_number_pos(dividend // divisor),
        magnitude,
        _say_number_pos(dividend % divisor),
    )


def _join(*args):
    """Join parts of the number representation."""
    return ' '.join(filter(bool, args))


def ord_util(n):
    """Return the ordinal representation of a number."""
    if not isinstance(n, int):
        logger.error("Input must be an integer.")
        raise ValueError("Input must be an integer.")

    logger.info(f"Converting to ordinal: {n}")
    return str(n) + ("th" if 4 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th"))


# Example usage
if __name__ == "__main__":
    try:
        number = 123456789
        logger.info(f"Number: {number}, In Words: {say_number(number)}")
        ordinal = 21
        logger.info(f"Ordinal: {ordinal}, Representation: {ord_util(ordinal)}")
    except Exception as e:
        logger.critical(f"Error occurred: {e}")
