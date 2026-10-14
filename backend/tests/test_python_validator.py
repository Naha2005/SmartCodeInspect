import pytest
from validators.python_validator import validate_python_source


def test_valid_python_source():
    code = """
def calculate_sum(a, b):
    # Safe helper function
    return a + b

result = calculate_sum(10, 20)
print(result)
"""
    res = validate_python_source(code, filename="math_utils.py")
    assert res["valid_syntax"] is True
    assert res["language"] == "python"
    assert len(res["diagnostics"]) == 0
    assert "successfully" in res["message"]
    assert res["total_lines"] > 0
    assert res["parsed_ast"] is not None


def test_invalid_python_source_syntax_error():
    bad_code = "def broken_func(x\n    return x * 2"
    res = validate_python_source(bad_code, filename="bad.py")
    assert res["valid_syntax"] is False
    assert len(res["diagnostics"]) > 0
    diag = res["diagnostics"][0]
    assert diag["severity"] == "error"
    assert diag["line"] == 1
    assert "SyntaxError" in diag["message"]
    assert res["parsed_ast"] is None


def test_empty_python_source():
    res = validate_python_source("", filename="empty.py")
    assert res["valid_syntax"] is False
    assert len(res["diagnostics"]) == 1
    assert "0 bytes" in res["diagnostics"][0]["message"]


def test_none_python_source():
    res = validate_python_source(None)
    assert res["valid_syntax"] is False
    assert "empty" in res["diagnostics"][0]["message"].lower()


def test_invalid_type_python_source():
    res = validate_python_source({"code": "print(1)"})
    assert res["valid_syntax"] is False
    assert "invalid data type" in res["message"].lower()


def test_oversized_python_source():
    large_code = "x = 1\n" * 50000
    res = validate_python_source(large_code, max_bytes=5000)
    assert res["valid_syntax"] is False
    assert "exceeds maximum allowed size" in res["diagnostics"][0]["message"]
