import pytest
from unittest.mock import patch
import subprocess
from validators.java_validator import (
    validate_java_source,
    detect_javac_availability,
    extract_primary_java_class,
    parse_javac_output
)


def test_detect_javac_availability():
    res = detect_javac_availability()
    assert isinstance(res, dict)
    assert "available" in res
    # On this machine javac 25 is installed
    assert res["available"] is True


def test_extract_primary_java_class():
    code1 = "public class OrderProcessor { public static void main(String[] args) {} }"
    assert extract_primary_java_class(code1) == "OrderProcessor"

    code2 = "package com.example;\npublic interface SecurityFilter {}"
    assert extract_primary_java_class(code2) == "SecurityFilter"

    code3 = "class HelperOnly {}"
    assert extract_primary_java_class(code3) == "HelperOnly"

    code4 = "// No class here\nint x = 5;"
    assert extract_primary_java_class(code4) is None


def test_valid_java_compilation():
    code = """
public class Calculator {
    public static int add(int a, int b) {
        return a + b;
    }

    public static void main(String[] args) {
        System.out.println("Result: " + add(5, 7));
    }
}
"""
    res = validate_java_source(code, filename="Calculator.java")
    assert res["valid_syntax"] is True
    assert res["language"] == "java"
    assert res["filename"] == "Calculator.java"
    assert "successful" in res["message"].lower()


def test_invalid_java_compilation_syntax_error():
    bad_code = """
public class BrokenSyntax {
    public static void main(String[] args) {
        int x = 10 // missing semicolon
        System.out.println(x)
    }
}
"""
    res = validate_java_source(bad_code, filename="BrokenSyntax.java")
    assert res["valid_syntax"] is False
    assert len(res["diagnostics"]) > 0
    first_diag = res["diagnostics"][0]
    assert first_diag["severity"] in ("error", "warning")
    assert first_diag["line"] > 0
    assert "failed" in res["message"].lower()


def test_empty_and_null_java_input():
    res_empty = validate_java_source("")
    assert res_empty["valid_syntax"] is False

    res_null = validate_java_source(None)
    assert res_null["valid_syntax"] is False

    res_type = validate_java_source(12345)
    assert res_type["valid_syntax"] is False


def test_oversized_java_input():
    huge_code = "public class Big { int a = 1; }\n" * 10000
    res = validate_java_source(huge_code, max_bytes=2000)
    assert res["valid_syntax"] is False
    assert "payload too large" in res["message"].lower()


def test_parse_javac_output():
    javac_text = "Test.java:12: error: ';' expected\n        int a = 5\n                 ^\n1 error"
    diags = parse_javac_output(javac_text, "Test.java")
    assert len(diags) == 1
    assert diags[0]["line"] == 12
    assert diags[0]["severity"] == "error"
    assert "';' expected" in diags[0]["message"]
    assert diags[0]["evidence"] == "int a = 5"
    assert diags[0]["column"] == 17
