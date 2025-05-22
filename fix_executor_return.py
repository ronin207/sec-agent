#!/usr/bin/env python3
"""
Script to fix the missing except/finally block in scan_executor.py
"""
import os
import re

# Fix scan_executor.py
print("Fixing return statement in scan_executor.py...")

with open("backend/core/scan_executor.py", "r") as file:
    lines = file.readlines()

fixed_lines = []
in_try_block = False
needs_fixing = False
try_index = -1

for i, line in enumerate(lines):
    fixed_lines.append(line)
    
    # Track when we're in a try block
    if "try:" in line and not line.strip().startswith("#"):
        in_try_block = True
        try_index = i
    
    # Check if we have a bare return inside a try block
    if in_try_block and "return {" in line and not any(x in line for x in ["except", "finally"]):
        needs_fixing = True
        # We've found an issue, continue adding lines until we see the end of the return statement
        j = i + 1
        while j < len(lines) and "}" not in lines[j]:
            j += 1
        
        # Add the except block after the return statement is complete
        if j < len(lines) and "}" in lines[j]:
            fixed_lines.append("        except Exception as e:\n")
            fixed_lines.append("            logger.error(f\"Error: {str(e)}\")\n")
            fixed_lines.append("            return None\n")
            in_try_block = False
    
    # Reset try block tracking when we see except or finally
    if in_try_block and any(x in line for x in ["except ", "finally:"]):
        in_try_block = False

if needs_fixing:
    with open("backend/core/scan_executor.py", "w") as file:
        file.writelines(fixed_lines)
    print("Fixed missing except/finally block in scan_executor.py")
else:
    print("No issues found or already fixed in scan_executor.py") 