#!/usr/bin/env python3
"""
Script to fix missing imports in scanner files
"""
import os
import re

SCANNERS_DIR = "/home/cerberusmrxi/Desktop/new project/cerberus-sentinel/engine/scanners"

def fix_scanner_imports(filepath):
    """Add missing imports to a scanner file if needed"""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Check if Target and List are used but not imported
    uses_target = 'target: Target' in content
    uses_list = '-> List[Vulnerability]' in content
    
    has_target_import = 'from ..core.target import Target' in content
    has_list_import = 'from typing import List' in content
    
    if not (uses_target or uses_list):
        return False  # No changes needed
    
    # Find the imports section (after docstring, before class)
    lines = content.split('\n')
    
    # Track changes
    modified = False
    insert_index = None
    
    # Find where to insert imports (after existing imports from .base)
    for i, line in enumerate(lines):
        if 'from .base import' in line:
            insert_index = i + 1
            break
    
    if insert_index is None:
        print(f"Could not find import section in {filepath}")
        return False
    
    # Insert missing imports
    new_imports = []
    if uses_list and not has_list_import:
        new_imports.append('from typing import List')
        modified = True
    
    if uses_target and not has_target_import:
        new_imports.append('from ..core.target import Target')
        modified = True
    
    if modified:
        # Insert new imports
        for imp in reversed(new_imports):
            lines.insert(insert_index, imp)
        
        # Write back
        with open(filepath, 'w') as f:
            f.write('\n'.join(lines))
        
        print(f"✓ Fixed {os.path.basename(filepath)}")
        return True
    
    return False

def main():
    """Fix all scanner files"""
    scanner_files = [
        f for f in os.listdir(SCANNERS_DIR)
        if f.endswith('.py') and f not in ['__init__.py', 'base.py']
    ]
    
    fixed_count = 0
    for filename in scanner_files:
        filepath = os.path.join(SCANNERS_DIR, filename)
        if fix_scanner_imports(filepath):
            fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")

if __name__ == '__main__':
    main()
