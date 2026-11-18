"""
Sample 1: Low Complexity (Clean & Secure)
Language: Python
Purpose: Demonstrates baseline clean code adhering to OWASP & clean architecture standards.
Expected Score: 100/100 Health Score (Zero active vulnerabilities or code smells).
"""

import math
from typing import List, Union, Dict


def calculate_statistics(numbers: List[Union[int, float]]) -> Dict[str, float]:
    """
    Safely calculate basic statistical metrics without eval() or unsafe dynamic execution.
    Input validation guarantees robust boundary handling.
    """
    if not numbers:
        return {"count": 0.0, "mean": 0.0, "variance": 0.0, "std_dev": 0.0}

    count = float(len(numbers))
    mean = sum(numbers) / count
    variance = sum((x - mean) ** 2 for x in numbers) / count
    std_dev = math.sqrt(variance)

    return {
        "count": count,
        "mean": round(mean, 4),
        "variance": round(variance, 4),
        "std_dev": round(std_dev, 4)
    }


if __name__ == "__main__":
    dataset = [12.5, 45.2, 78.1, 99.4, 32.0]
    results = calculate_statistics(dataset)
    # Production logging or clean return
