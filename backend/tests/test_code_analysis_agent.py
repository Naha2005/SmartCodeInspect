import pytest
from agents.code_analysis_agent import CodeAnalysisAgent


@pytest.fixture
def agent():
    return CodeAnalysisAgent()


# Sample Python codebase containing known code quality issues
PYTHON_QUALITY_DEFECTS_CODE = """from math import *

def BadNamingFunction(param_a, param_b, param_c, param_d, param_e, param_f):
    items = []
    print("Debug: Starting processing")
    try:
        val = 86400 * 7
        f = open("temp.log", "r")
        if param_a > 10:
            if param_b > 20:
                if param_c > 30:
                    if param_d > 40:
                        items.append(val)
        if param_a > 0 and param_b > 0 and param_c > 0 and param_d > 0:
            print("All positive")
    except Exception:
        pass
    return items

def compute_complex(x):
    total = 0
    if x == 1:
        total += 1
    elif x == 2:
        total += 2
    elif x == 3:
        total += 3
    elif x == 4:
        total += 4
    elif x == 5:
        total += 5
    elif x == 6:
        total += 6
    elif x == 7:
        total += 7
    elif x == 8:
        total += 8
    elif x == 9:
        total += 9
    return total

def function_with_mutable_defaults(records=[]):
    records.append("entry")
    return records
"""

# Sample Clean Python codebase
PYTHON_CLEAN_CODE = """\"\"\"High quality clean math utility module.\"\"\"
from typing import List


def calculate_average(values: List[float]) -> float:
    \"\"\"Calculate the arithmetic mean of a list of floats safely.\"\"\"
    if not values:
        return 0.0
    return sum(values) / len(values)
"""

# Sample Java codebase containing known code quality issues
JAVA_QUALITY_DEFECTS_CODE = """import java.util.*;
import java.io.*;

public class badNamingClass {
    public void BadMethodName(int a, int b, int c, int d, int e, int f) {
        System.out.println("Processing transaction: " + a);
        try {
            FileInputStream fis = new FileInputStream("audit.log");
            if (a > 0 && b > 0 && c > 0 && d > 0) {
                System.out.println("Positive coordinates");
            }
        } catch (Exception e_err) {
        }
    }
}
"""

# Sample Clean Java codebase
JAVA_CLEAN_CODE = """package com.example.service;

import java.util.List;

public class MathStatisticsCalculator {
    public double calculateMean(List<Double> numbers) {
        if (numbers == null || numbers.isEmpty()) {
            return 0.0;
        }
        double sum = 0.0;
        for (double n : numbers) {
            sum += n;
        }
        return sum / numbers.size();
    }
}
"""


def test_python_code_smells_detected(agent):
    findings = agent.analyze(PYTHON_QUALITY_DEFECTS_CODE, language="python")
    rule_ids = {f.rule_id for f in findings}

    # Verify Wildcard import smell (SMELL-PY-005)
    assert "SMELL-PY-005" in rule_ids, "Should detect wildcard import smell"

    # Verify Long parameter list smell (SMELL-PY-002)
    assert "SMELL-PY-002" in rule_ids, "Should detect long parameter list (>5 params)"

    # Verify Empty exception handler smell (SMELL-PY-004)
    assert "SMELL-PY-004" in rule_ids, "Should detect empty exception handler (pass)"


def test_python_complexity_issues_detected(agent):
    findings = agent.analyze(PYTHON_QUALITY_DEFECTS_CODE, language="python")
    rule_ids = {f.rule_id for f in findings}

    # Verify High Cyclomatic Complexity (COMPLEX-PY-001)
    assert "COMPLEX-PY-001" in rule_ids, "Should detect high cyclomatic complexity in compute_complex"

    # Verify Deep Nesting (COMPLEX-PY-002)
    assert "COMPLEX-PY-002" in rule_ids, "Should detect deep nesting (arrow anti-pattern)"

    # Verify Complex Boolean Expression (COMPLEX-PY-003)
    assert "COMPLEX-PY-003" in rule_ids, "Should detect complex compound boolean condition"


def test_python_design_anti_patterns_detected(agent):
    findings = agent.analyze(PYTHON_QUALITY_DEFECTS_CODE, language="python")
    rule_ids = {f.rule_id for f in findings}

    # Verify Mutable Default Argument (DESIGN-PY-001)
    assert "DESIGN-PY-001" in rule_ids, "Should detect mutable default argument records=[]"

    # Verify Magic Numbers (DESIGN-PY-004)
    assert "DESIGN-PY-004" in rule_ids, "Should detect magic number 86400"


def test_python_poor_coding_practices_detected(agent):
    findings = agent.analyze(PYTHON_QUALITY_DEFECTS_CODE, language="python")
    rule_ids = {f.rule_id for f in findings}

    # Verify Print statements in production (PRACTICE-PY-001)
    assert "PRACTICE-PY-001" in rule_ids, "Should detect print() statement in production code"

    # Verify Unmanaged file open without with (PRACTICE-PY-002)
    assert "PRACTICE-PY-002" in rule_ids, "Should detect open() without with context manager"

    # Verify PEP 8 naming violation (PRACTICE-PY-003)
    assert "PRACTICE-PY-003" in rule_ids, "Should detect BadNamingFunction not following snake_case"


def test_python_severity_scoring(agent):
    findings = agent.analyze(PYTHON_QUALITY_DEFECTS_CODE, language="python")
    assert len(findings) > 0

    for f in findings:
        # Every finding must have a positive severity score
        assert f.severity_score > 0.0, f"Finding {f.rule_id} must have severity_score > 0"
        assert f.agent == "Code Analysis Agent"
        assert f.category in ("Code Smell", "Complexity", "Design Anti-Pattern", "Poor Coding Practice")

        # Check severity score ranges match severity labels
        if f.severity == "High":
            assert f.severity_score >= 7.0
        elif f.severity == "Medium":
            assert 4.0 <= f.severity_score <= 7.0
        elif f.severity == "Low":
            assert 2.0 <= f.severity_score <= 4.0
        elif f.severity == "Informational":
            assert f.severity_score <= 2.0


def test_java_code_analysis_defects_detected(agent):
    findings = agent.analyze(JAVA_QUALITY_DEFECTS_CODE, language="java")
    rule_ids = {f.rule_id for f in findings}

    # Verify Wildcard import (SMELL-JV-005)
    assert "SMELL-JV-005" in rule_ids, "Should detect java wildcard import"

    # Verify System.out in production (PRACTICE-JV-001)
    assert "PRACTICE-JV-001" in rule_ids, "Should detect System.out.println in production"

    # Verify Empty catch block (SMELL-JV-004)
    assert "SMELL-JV-004" in rule_ids, "Should detect empty catch block"

    # Verify Unmanaged stream resource (PRACTICE-JV-002)
    assert "PRACTICE-JV-002" in rule_ids, "Should detect FileInputStream without try-with-resources"

    # Verify Naming violation (PRACTICE-JV-003)
    assert "PRACTICE-JV-003" in rule_ids, "Should detect method starting with uppercase"


def test_clean_codebases_low_findings(agent):
    py_findings = agent.analyze(PYTHON_CLEAN_CODE, language="python")
    # Clean Python code with docstring and snake_case should have 0 quality findings
    assert len(py_findings) == 0, f"Clean Python code should have 0 findings, got: {[f.rule_id for f in py_findings]}"

    jv_findings = agent.analyze(JAVA_CLEAN_CODE, language="java")
    assert len(jv_findings) == 0, f"Clean Java code should have 0 findings, got: {[f.rule_id for f in jv_findings]}"


def test_python_unique_rule_ids_and_parameter_types(agent):
    # Test class naming violation (PRACTICE-PY-005) vs function naming violation (PRACTICE-PY-003)
    code = """class bad_class_name:
    def good_function(self):
        pass

def BadFunctionName():
    pass
"""
    findings = agent.analyze(code, language="python")
    rule_ids = {f.rule_id for f in findings}
    assert "PRACTICE-PY-005" in rule_ids, "Class naming violation should use unique PRACTICE-PY-005"
    assert "PRACTICE-PY-003" in rule_ids, "Function naming violation should use PRACTICE-PY-003"

    # Test parameter counting including posonlyargs, kwonlyargs, *args, **kwargs
    code_params = """def complex_sig(a, b, /, c, *args, d, e, **kwargs):
    pass
"""
    f_params = agent.analyze(code_params, language="python")
    assert any(f.rule_id == "SMELL-PY-002" for f in f_params), "Should count all parameter types (>5)"


def test_python_file_open_ast_accuracy(agent):
    # Test multiline with statement -> no false positive
    code_safe_multiline = """with (
    open("test.txt", "r") as f
):
    data = f.read()
"""
    f_safe = agent.analyze(code_safe_multiline, language="python")
    assert not any(f.rule_id == "PRACTICE-PY-002" for f in f_safe), "Multiline with statement should not be flagged as unmanaged open"

    # Test unmanaged open call -> flagged
    code_unsafe = """f = open("leak.txt", "w")
f.write("hello")
"""
    f_unsafe = agent.analyze(code_unsafe, language="python")
    assert any(f.rule_id == "PRACTICE-PY-002" for f in f_unsafe), "Unmanaged open call should be flagged"


def test_java_structural_and_nesting_accuracy(agent):
    # Test control-flow nesting: class and method braces do NOT trigger nesting
    code_normal_nesting = """public class OuterClass {
    public class InnerClass {
        public void execute() {
            if (true) {
                System.out.println("Normal nesting depth 1");
            }
        }
    }
}
"""
    f_normal = agent.analyze(code_normal_nesting, language="java")
    assert not any(f.rule_id == "COMPLEX-JV-002" for f in f_normal), "Class and method braces must not count toward control nesting"

    # Test constructor name matching class is NOT flagged as method naming violation
    code_constructor = """public class PaymentGateway {
    public PaymentGateway(String config) {
        // Constructor, should not flag PRACTICE-JV-003
    }
}
"""
    f_ctor = agent.analyze(code_constructor, language="java")
    assert not any(f.rule_id == "PRACTICE-JV-003" for f in f_ctor), "Constructor should not be flagged as method naming violation"

    # Test multiline method declaration and parameter counting with generics
    code_multiline = """public class MultiLineService {
    public void processData(
        java.util.Map<String, Integer> map,
        java.util.List<String> list,
        int x,
        int y,
        int z,
        String extra
    ) {
        // 6 parameters across multiple lines
    }
}
"""
    f_multi = agent.analyze(code_multiline, language="java")
    assert any(f.rule_id == "SMELL-JV-002" for f in f_multi), "Multiline method with 6 params should be detected as SMELL-JV-002"

