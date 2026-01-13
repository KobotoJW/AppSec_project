#!/usr/bin/env python3
import os
import io
import sys
import tokenize

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
EXCLUDED_DIRS = {'.git', '__pycache__', 'media'}
TEXT_EXTS = {'.sh', '.yml', '.yaml', '.txt', '.env'}
TARGET_FILES = {'requirements.txt', 'Dockerfile', 'docker-compose.yml'}

changed = []

def process_python(path):
    try:
        with open(path, 'rb') as f:
            tokens = list(tokenize.tokenize(f.readline))
    except Exception:
        return False
    new_tokens = []
    for tok in tokens:
                                                           
        if tok.type == tokenize.COMMENT:
                                                                                     
                                                              
            if tok.string.startswith('#!'):
                new_tokens.append(tok)
            else:
                continue
        else:
            new_tokens.append(tok)
    try:
        new_bytes = tokenize.untokenize(new_tokens)
        if isinstance(new_bytes, bytes):
            new_content = new_bytes.decode('utf-8')
        else:
            new_content = new_bytes
    except Exception:
        return False
    with open(path, 'r', encoding='utf-8') as f:
        orig = f.read()
    if orig != new_content:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return True
    return False

def strip_hash_outside_quotes(line):
    out = []
    i = 0
    n = len(line)
    in_sq = in_dq = False
    escaped = False
    while i < n:
        ch = line[i]
        if ch == '\\' and not escaped:
            escaped = True
            out.append(ch)
            i += 1
            continue
        if ch == "'" and not escaped and not in_dq:
            in_sq = not in_sq
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not escaped and not in_sq:
            in_dq = not in_dq
            out.append(ch)
            i += 1
            continue
        if ch == '#' and not in_sq and not in_dq:
                                                              
                                                         
            return ''.join(out).rstrip() + ("\n" if line.endswith('\n') else '')
        out.append(ch)
        escaped = False
        i += 1
    return ''.join(out)

def process_text(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return False
    new_lines = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith('#'):
                                      
            continue
        new_line = strip_hash_outside_quotes(line)
        new_lines.append(new_line)
    new_content = ''.join(new_lines)
    with open(path, 'r', encoding='utf-8') as f:
        orig = f.read()
    if orig != new_content:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return True
    return False

for dirpath, dirnames, filenames in os.walk(ROOT):
                        
    parts = set(os.path.relpath(dirpath, ROOT).split(os.sep))
    if parts & EXCLUDED_DIRS:
        continue
                             
    if any(p.startswith('.') for p in os.path.basename(dirpath).split()):
        pass
    for name in filenames:
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, ROOT)
        _, ext = os.path.splitext(name)
        try:
            if ext == '.py':
                if process_python(path):
                    changed.append(rel)
            elif name in TARGET_FILES or ext in TEXT_EXTS:
                if process_text(path):
                    changed.append(rel)
        except Exception as e:
            print(f"Error processing {rel}: {e}", file=sys.stderr)

print(f"Processed root: {ROOT}")
if changed:
    print(f"Modified {len(changed)} files:")
    for p in changed:
        print(p)
else:
    print("No files changed.")
