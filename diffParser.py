import json
import os
import re

MAX_CHUNK_BYTES = 64 * 1024


def parse_request_body(json_body):
    try:
        data = json_body if isinstance(json_body, dict) else json.loads(json_body)
    except (TypeError, json.JSONDecodeError):
        return []

    diff_payload = data.get('diff', '') if isinstance(data, dict) else ''
    if isinstance(diff_payload, dict):
        diff_payload = diff_payload.get('diff', '')

    if not diff_payload:
        return []

    diff_text = normalize_diff_text(diff_payload)
    if diff_text:
        return parse_diff_file(diff_text)

    return []


def normalize_diff_text(diff_payload):
    if not isinstance(diff_payload, str):
        return ''

    stripped = diff_payload.strip()
    if not stripped:
        return ''

    if stripped.startswith('{') and stripped.endswith('}'):
        try:
            nested = json.loads(stripped)
            if isinstance(nested, dict):
                nested_diff = nested.get('diff', '')
                if nested_diff:
                    return normalize_diff_text(nested_diff)
        except json.JSONDecodeError:
            return stripped

    if stripped.startswith('diff --git ') or stripped.startswith('@@') or '\n' in stripped:
        return stripped

    if os.path.exists(stripped):
        with open(stripped, encoding='utf-8') as diff_file:
            return diff_file.read()

    return stripped


def extract_diff_file_blocks(diff_text):
    blocks = []
    current_block = []

    for line in diff_text.splitlines(keepends=True):
        if line.startswith('diff --git '):
            if current_block:
                blocks.append(''.join(current_block))
            current_block = [line]
        elif current_block:
            current_block.append(line)

    if current_block:
        blocks.append(''.join(current_block))

    return blocks


def chunk_diff_text(diff_text, max_chunk_bytes=MAX_CHUNK_BYTES):
    if not isinstance(diff_text, str):
        return []

    stripped = diff_text.strip()
    if not stripped:
        return []

    blocks = extract_diff_file_blocks(stripped)
    if not blocks:
        return [stripped]

    chunks = []
    current_chunk = []
    current_size = 0

    for block in blocks:
        block_size = len(block.encode('utf-8'))

        if block_size > max_chunk_bytes:
            if current_chunk:
                chunks.append(''.join(current_chunk))
                current_chunk = []
                current_size = 0
            chunks.append(block)
            continue

        if current_chunk and current_size + block_size > max_chunk_bytes:
            chunks.append(''.join(current_chunk))
            current_chunk = [block]
            current_size = block_size
        else:
            current_chunk.append(block)
            current_size += block_size

    if current_chunk:
        chunks.append(''.join(current_chunk))

    return chunks


def parse_diff_file(diff_text):
    files = []
    current_file = None
    current_old_line = None
    current_new_line = None

    for line in diff_text.splitlines():
        if line.startswith('diff --git '):
            if current_file:
                files.append(current_file)

            file_path = line.split(' b/', 1)[1] if ' b/' in line else line.split()[-1]
            current_file = {
                'path': file_path,
                'added_lines': 0,
                'removed_lines': 0,
                'hunks': 0,
                'changes': []
            }
            current_old_line = None
            current_new_line = None

        elif line.startswith('@@') and current_file:
            current_file['hunks'] += 1
            old_match = re.search(r'-(\d+)(?:,(\d+))?', line)
            new_match = re.search(r'\+(\d+)(?:,(\d+))?', line)

            current_old_line = int(old_match.group(1)) if old_match else None
            current_new_line = int(new_match.group(1)) if new_match else None

        elif current_file and line.startswith('+') and not line.startswith('+++'):
            current_file['added_lines'] += 1
            current_file['changes'].append({
                'type': 'added',
                'line': current_new_line if current_new_line is not None else 0,
                'text': line[1:]
            })
            if current_new_line is not None:
                current_new_line += 1

        elif current_file and line.startswith('-') and not line.startswith('---'):
            current_file['removed_lines'] += 1
            current_file['changes'].append({
                'type': 'removed',
                'line': current_old_line if current_old_line is not None else 0,
                'text': line[1:]
            })
            if current_old_line is not None:
                current_old_line += 1

        elif current_file and line.startswith(' '):
            if current_old_line is not None:
                current_old_line += 1
            if current_new_line is not None:
                current_new_line += 1

    if current_file:
        files.append(current_file)

    return files

