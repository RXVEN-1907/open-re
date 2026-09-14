import re
import json

warnings = []

with open('clippy_output.txt', 'r') as f:
    lines = f.readlines()

i = 0
while i < len(lines):
    line = lines[i]
    if line.startswith('warning: unused import:') or line.startswith('warning: unused imports:'):
        if line.startswith('warning: unused import:'):
            msg = line[len('warning: unused import:'):].strip()
        else:
            msg = line[len('warning: unused imports:'):].strip()
        
        j = i + 1
        while j < len(lines) and not lines[j].startswith('  --> '):
            j += 1
        if j < len(lines):
            loc_line = lines[j].strip()
            loc_part = loc_line[4:]  # remove '  --> '
            if loc_part.count(':') >= 2:
                last_colon = loc_part.rfind(':')
                second_last_colon = loc_part.rfind(':', 0, last_colon)
                file_name = loc_part[:second_last_colon]
                line_number = loc_part[second_last_colon+1:last_colon]
            else:
                file_name = loc_part
                line_number = '0'
        else:
            file_name = ''
            line_number = '0'
        
        import_matches = re.findall(r'`([^`]*)`', msg)
        warnings.append({
            'file': file_name,
            'line': int(line_number) if line_number.isdigit() else 0,
            'imports': import_matches
        })
        i += 1
    else:
        i += 1

print(json.dumps({'warnings': warnings}, indent=2))
