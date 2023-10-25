import re

# Define the source URL pattern and the destination URL
source_url_pattern = r"https://raw.githubusercontent.com/blankshiro/ShiroWriteups/main/HackTheBox/Legacy/"
destination_url = "https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Legacy/"

# Update the file path to your Markdown file
file_path = r"C:\Users\edwin\Documents\GitHub\blankshiro.github.io\_posts\2022-12-01-HTB-Legacy.md"

# Read the Markdown file with 'utf-8' encoding
with open(file_path, "r", encoding="utf-8") as file:
    content = file.read()

# Use regular expressions to replace the source URL pattern with the destination URL
pattern = re.escape(source_url_pattern) + r"(.*?\.png)"
replacement = destination_url + r"\1?raw=true"
content = re.sub(pattern, replacement, content)

# Write the updated content back to the Markdown file
with open(file_path, "w", encoding="utf-8") as file:
    file.write(content)

print("Replacement completed successfully.")
