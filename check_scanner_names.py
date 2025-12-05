#!/usr/bin/env python3
"""
Script to check all scanner class names in the scanners directory
"""
import os
import re

SCANNERS_DIR = "/home/cerberusmrxi/Desktop/new project/cerberus-sentinel/engine/scanners"

def get_class_name(filepath):
    """Extract class name from scanner file"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Find class definition
    match = re.search(r'class (\w+)\(BaseScanner\):', content)
    if match:
        return match.group(1)
    return None

def main():
    """Check all scanner files"""
    scanner_files = [
        f for f in os.listdir(SCANNERS_DIR)
        if f.endswith('.py') and f not in ['__init__.py', 'base.py']
    ]
    
    results = {}
    for filename in sorted(scanner_files):
        filepath = os.path.join(SCANNERS_DIR, filename)
        class_name = get_class_name(filepath)
        if class_name:
            module_name = filename.replace('.py', '')
            results[module_name] = class_name
    
    # Print results in a format easy to copy
    for module, classname in results.items():
        print(f"from engine.scanners.{module} import {classname}")

if __name__ == '__main__':
    main()
