file_path = "src/docs/api-reference.md"

with open(file_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Remove first line if it's ```markdown
if lines and lines[0].rstrip() == "```markdown":
    lines = lines[1:]

with open(file_path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("Removed ```markdown from line 1")
