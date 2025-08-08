# analyzer/utils.py

import math

def calculate_entropy(data):
    """
    Calculates Shannon entropy of a string.
    """
    if not data:
        return 0

    frequency = {}
    for char in data:
        if char in frequency:
            frequency[char] += 1
        else:
            frequency[char] = 1

    entropy = 0
    for freq in frequency.values():
        p = freq / len(data)
        entropy -= p * math.log2(p)

    return round(entropy, 3)
