import re

file_path = "src/docs/api-reference.md"

with open(file_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Remove lines that only contain "text" (with optional whitespace)
cleaned_lines = [line for line in lines if line.strip() != "text"]

with open(file_path, "w", encoding="utf-8") as f:
    f.writelines(cleaned_lines)

print(f'Removed {len(lines) - len(cleaned_lines)} lines with "text"')
