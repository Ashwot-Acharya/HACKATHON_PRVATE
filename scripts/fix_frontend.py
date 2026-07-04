import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import os
import glob

def replace_in_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Replace fetch urls
    content = content.replace("import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'", "(`http://${window.location.hostname}:8000`)")
    
    with open(filepath, 'w') as f:
        f.write(content)

for root, _, files in os.walk('frontend/src'):
    for file in files:
        if file.endswith('.tsx') or file.endswith('.ts'):
            replace_in_file(os.path.join(root, file))

print("Done patching frontend URLs.")
