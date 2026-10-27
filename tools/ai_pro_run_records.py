"""Discover exact actor stages, excluding fallback descendants with the same prefix."""
import json

def stage_roles(root, stage, known_roles):
    roles = []
    for folder in root.glob(stage + '-*'):
        started = folder / 'started.json'
        if not folder.is_dir() or not started.is_file():
            continue
        metadata = json.loads(started.read_text(encoding='utf-8'))
        if metadata.get('stage') != stage:
            continue
        role = metadata.get('role')
        if role not in known_roles or folder.name != stage + '-' + role:
            raise ValueError('Actor stage/role/directory mismatch')
        roles.append(role)
    return sorted(roles)
