#!/usr/bin/env python3
"""
Script to fix syntax errors in scan_executor.py and helpers.py files
"""
import os
import re

# Fix scan_executor.py
print("Fixing scan_executor.py...")

with open("backend/core/scan_executor.py", "r") as file:
    content = file.read()

# Fix 1: Fix indentation error on line 190
content = re.sub(r'logger\.info\(f"Executing \{tool\.get\(\'name\'\)\} on \{target\}"\)\s+\n\s+tool_id = tool\.get\(\'id\', \'unknown\'\)\s+\n\s+start_time', 
                 'logger.info(f"Executing {tool.get(\'name\')} on {target}")\n        \n        tool_id = tool.get(\'id\', \'unknown\')\n        start_time', 
                 content)

# Write fixed content back to file
with open("backend/core/scan_executor.py", "w") as file:
    file.write(content)

# Fix helpers.py
print("Fixing helpers.py...")

with open("backend/utils/helpers.py", "r") as file:
    content = file.read()

# Fix 2: Fix f-string backslash issue by converting it to regular string concatenation
content = re.sub(r'return code\.replace\(\s+f"function \{function_match\.group\(1\)\}",\s+f"function \{function_match\.group\(1\)\}\\n\s+\{\\n\s+require\(msg\.sender == owner, \\"Not authorized\\"',
                 'return code.replace(\n                    f"function {function_match.group(1)}",\n                    "function " + function_match.group(1) + "\\n    {\\n        require(msg.sender == owner, \\"Not authorized\\""',
                 content)

# Write fixed content back to file
with open("backend/utils/helpers.py", "w") as file:
    file.write(content)

print("Fixes applied successfully!") 