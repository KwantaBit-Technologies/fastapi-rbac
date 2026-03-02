file_path = "src/docs/deployment.md"

with open(file_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Remove first line if it starts with ```
while lines and (lines[0].strip().startswith("```") or lines[0].strip() == ""):
    lines.pop(0)

# Remove last lines with ``` and empty
while lines and (
    lines[-1].strip() in ["```", "````", ""] or lines[-1].strip().startswith("```")
):
    lines.pop()

# Remove excessive blank lines (keep max 1 between sections)
cleaned = []
prev_blank = False
for line in lines:
    if line.strip() == "":
        if not prev_blank:
            cleaned.append(line)
            prev_blank = True
    else:
        cleaned.append(line)
        prev_blank = False

with open(file_path, "w", encoding="utf-8") as f:
    f.writelines(cleaned)

print("File properly formatted")
