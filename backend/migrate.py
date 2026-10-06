import glob
import os
import re

MODELS_DIR = "app/models"

def migrate_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()


    if "from sqlalchemy.orm import" in content and "Mapped" not in content:
        content = re.sub(r'(from sqlalchemy\.orm import )', r'\1Mapped, mapped_column, ', content, count=1)
    elif "Mapped" not in content:
        content = "from sqlalchemy.orm import Mapped, mapped_column\n" + content

    type_hints = {
        "Integer": "int",
        "String": "str",
        "Text": "str",
        "Float": "float",
        "Boolean": "bool",
        "DateTime": "datetime.datetime",
        "JSON": "dict | list",
    }
    
    lines = content.split('\n')
    new_lines = []
    
    for line in lines:
        if " = Column(" in line:
            match = re.search(r'^(\s+)([a-zA-Z0-9_]+)\s*=\s*Column\((.*?)\)(?:\s*#.*)?$', line)
            if match:
                indent = match.group(1)
                var_name = match.group(2)
                args = match.group(3)
                
                base_type_match = re.search(r'^([a-zA-Z0-9_]+)', args)
                base_type = base_type_match.group(1) if base_type_match else "Any"
                
                py_type = type_hints.get(base_type, "Any")
                
                if "nullable=True" in args or "nullable=True" in line:
                    py_type = f"{py_type} | None"
                    
                new_line = f"{indent}{var_name}: Mapped[{py_type}] = mapped_column({args})"
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        elif " = relationship(" in line:
            match = re.search(r'^(\s+)([a-zA-Z0-9_]+)\s*=\s*relationship\((.*?)\)(?:\s*#.*)?$', line)
            if match:
                indent = match.group(1)
                var_name = match.group(2)
                args = match.group(3)
                
                model_match = re.search(r'^["\']([^"\']+)["\']', args)
                rel_model = model_match.group(1) if model_match else "Any"
                
                is_plural = var_name.endswith('s')
                py_type = f"list[\"{rel_model}\"]" if is_plural else f"\"{rel_model}\""
                
                if "uselist=False" in args:
                    py_type = f"\"{rel_model}\""
                    
                new_line = f"{indent}{var_name}: Mapped[{py_type}] = relationship({args})"
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
            
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))

if __name__ == "__main__":
    for py_file in glob.glob(os.path.join(MODELS_DIR, "*.py")):
        if not py_file.endswith("__init__.py"):
            migrate_file(py_file)
    print("Migration complete!")
