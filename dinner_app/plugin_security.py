"""Plugin security utilities.

This module provides security measures for the plugin system.
While plugins have full Python access, these measures help prevent
accidental misuse and common attack vectors.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import NamedTuple


class PluginSecurityCheck(NamedTuple):
    """Result of a plugin security check."""

    is_safe: bool
    warnings: list[str]
    errors: list[str]


# Dangerous imports that plugins should not use
DANGEROUS_IMPORTS = {
    "os": "Can access filesystem and execute commands",
    "subprocess": "Can execute arbitrary system commands",
    "shutil": "Can modify/delete files",
    "socket": "Can make network connections",
    "http": "Can make HTTP requests",
    "urllib": "Can make network requests",
    "ftplib": "Can access FTP servers",
    "smtplib": "Can send emails",
    "ssl": "Can make secure connections",
    "ctypes": "Can call C functions directly",
    "multiprocessing": "Can spawn system processes",
    "pickle": "Can deserialize untrusted data",
    "marshal": "Can deserialize code objects",
    "code": "Can compile and execute code",
    "eval": "Can execute arbitrary code",
    "exec": "Can execute arbitrary code",
    "__import__": "Can import any module",
}

# Dangerous function calls
DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",  # Can read/write files
    "input",  # Can hang waiting for input
    "getattr",  # Can access any attribute
    "setattr",  # Can set any attribute
    "delattr",  # Can delete attributes
    "globals",  # Can access global namespace
    "locals",  # Can access local namespace
    "vars",  # Can access __dict__
}

# Dangerous attribute access patterns (for obfuscation detection)
DANGEROUS_ATTRIBUTES = {
    "__builtins__",
    "__class__",
    "__bases__",
    "__subclasses__",
    "__mro__",
    "__globals__",
    "__code__",
    "__dict__",
    "__import__",
    "__loader__",
    "__spec__",
}

# Dangerous subscript patterns (string keys that indicate malicious intent)
DANGEROUS_SUBSCRIPTS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "__builtins__",
    "os",
    "subprocess",
    "system",
    "popen",
}


def check_plugin_source(source: str, filename: str = "<plugin>") -> PluginSecurityCheck:
    """
    Analyze plugin source code for security issues.

    This is a static analysis check and cannot catch all malicious code,
    but it helps identify common dangerous patterns.

    Args:
        source: Plugin source code
        filename: Name of the plugin file

    Returns:
        PluginSecurityCheck with safety status and any warnings/errors
    """
    warnings = []
    errors = []

    # Check for null bytes (crash ast.parse)
    if "\x00" in source:
        return PluginSecurityCheck(False, [], ["Source contains null bytes"])

    try:
        tree = ast.parse(source, filename)
    except SyntaxError as e:
        return PluginSecurityCheck(False, [], [f"Syntax error: {e}"])
    except ValueError as e:
        return PluginSecurityCheck(False, [], [f"Invalid source: {e}"])

    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".")[0]
                if module in DANGEROUS_IMPORTS:
                    errors.append(
                        f"Line {node.lineno}: Imports '{module}' - {DANGEROUS_IMPORTS[module]}"
                    )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module = node.module.split(".")[0]
                if module in DANGEROUS_IMPORTS:
                    errors.append(
                        f"Line {node.lineno}: Imports from '{module}' - {DANGEROUS_IMPORTS[module]}"
                    )

        # Check dangerous function calls
        elif isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in DANGEROUS_CALLS:
                warnings.append(f"Line {node.lineno}: Calls '{func_name}' which may be dangerous")

        # Check dangerous attribute access (e.g., obj.__class__.__bases__)
        elif isinstance(node, ast.Attribute):
            if node.attr in DANGEROUS_ATTRIBUTES:
                errors.append(
                    f"Line {node.lineno}: Accesses '{node.attr}' - potential code execution bypass"
                )

        # Check dangerous subscript access (e.g., __builtins__['eval'])
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            key = str(node.slice.value).lower()
            if key in DANGEROUS_SUBSCRIPTS:
                errors.append(
                    f"Line {node.lineno}: Subscript access to '{node.slice.value}' - potential bypass"
                )

    is_safe = len(errors) == 0
    return PluginSecurityCheck(is_safe, warnings, errors)


def compute_plugin_hash(filepath: Path) -> str:
    """
    Compute SHA-256 hash of a plugin file.

    This can be used to verify plugin integrity.

    Args:
        filepath: Path to the plugin file

    Returns:
        Hex-encoded SHA-256 hash
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def validate_plugin_file(filepath: Path) -> PluginSecurityCheck:
    """
    Validate a plugin file for security issues.

    Args:
        filepath: Path to the plugin file

    Returns:
        PluginSecurityCheck with results
    """
    if not filepath.exists():
        return PluginSecurityCheck(False, [], [f"File not found: {filepath}"])

    if filepath.suffix != ".py":
        return PluginSecurityCheck(False, [], ["Plugin must be a .py file"])

    if not filepath.name.startswith("plugin_"):
        return PluginSecurityCheck(False, [], ["Plugin filename must start with 'plugin_'"])

    try:
        source = filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return PluginSecurityCheck(False, [], ["Plugin must be valid UTF-8"])

    return check_plugin_source(source, str(filepath))
