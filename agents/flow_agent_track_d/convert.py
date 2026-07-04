import json

def py_to_ipynb(py_path, ipynb_path):
    with open(py_path, 'r', encoding='utf-8') as f:
        code = f.read()

    cells = []
    # Split by the separator used in the file
    chunks = code.split("# ---------------------------------------------------------------------------")
    for idx, chunk in enumerate(chunks):
        if not chunk.strip():
            continue
        
        # Add the separator back for structure (except the first header)
        if idx > 0:
            content = "# ---------------------------------------------------------------------------" + chunk
        else:
            content = chunk

        cell = {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [line + "\n" for line in content.split("\n")]
        }
        # Remove trailing newline from the last string in source to match Jupyter spec
        if cell["source"]:
            cell["source"][-1] = cell["source"][-1].rstrip('\n')
        
        cells.append(cell)

    notebook = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "codemirror_mode": {"name": "ipython", "version": 3},
                "file_extension": ".py",
                "mimetype": "text/x-python",
                "name": "python",
                "nbconvert_exporter": "python",
                "pygments_lexer": "ipython3",
                "version": "3.8.0"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 4
    }

    with open(ipynb_path, 'w', encoding='utf-8') as f:
        json.dump(notebook, f, indent=1)

py_to_ipynb('flow_agent.py', 'flow_agent.ipynb')
print("flow_agent.ipynb has been overwritten with the fixed code!")
