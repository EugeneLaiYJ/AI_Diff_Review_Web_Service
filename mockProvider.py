import re

from diffParser import chunk_diff_text, normalize_diff_text, parse_request_body

# RULE_ID = severity
#           category
#           title

MOCK_001 = {
    'ruleId': 'MOCK_001',
    'severity': 'critical',
    'category': 'security',
    'title': 'eval usage',
    'pattern': ["eval("]
}
MOCK_002 = {
    'ruleId': 'MOCK_002',
    'severity': 'critical',
    'category': 'security',
    'title': 'hardcoded credential',
}
MOCK_003 = {
    'ruleId': 'MOCK_003',
    'severity': 'high',
    'category': 'security',
    'title': 'SQL string concatenation',
}
MOCK_004 = {
    'ruleId': 'MOCK_004',
    'severity': 'high',
    'category': 'correctness',
    'title': 'swallowed exception',
}
MOCK_005 = {
    'ruleId': 'MOCK_005',
    'severity': 'medium',
    'category': 'correctness',
    'title': 'loose null comparison',
}
MOCK_006 = {
    'ruleId': 'MOCK_006',
    'severity': 'medium',
    'category': 'performance',
    'title': 'deep-clone via JSON',
}
MOCK_007 = {
    'ruleId': 'MOCK_007',
    'severity': 'low',
    'category': 'style',
    'title': 'console.log left in',
}
MOCK_008 = {
    'ruleId': 'MOCK_008',
    'severity': 'low',
    'category': 'style',
    'title': 'unresolved marker',
}
MOCK_INJ = {
    'ruleId': 'MOCK_INJ',
    'severity': 'critical',
    'category': 'security',
    'title': 'prompt-injection content',
}


class MockFindings:
    def __init__(self, ruleId, path, line, evidence):
        self.ruleId = ruleId.get('ruleId', 'unknown')
        self.path = path
        self.line = line
        self.evidence = evidence
        self.severity = ruleId.get('severity', 'unknown')
        self.category = ruleId.get('category', 'unknown')
        self.title = ruleId.get('title', 'unknown')
        self.id = f'{self.ruleId}:{self.path}:{self.line}'

    def MockResponse(self):
        return {
            'id': self.id,
            'ruleId': str(self.ruleId),
            'path': self.path,
            'line': self.line,
            'severity': self.severity,
            'category': self.category,
            'title': self.title,
            'evidence': self.evidence,
        }

    def MockReport(self):
        return self.MockResponse()


def _matches_rule(change_text, rule_id):
    normalized = change_text.strip()

    if rule_id == 'MOCK_001':
        return 'eval(' in normalized
    if rule_id == 'MOCK_002':
        return bool(re.search(r'(api[_-]?key|secret)', normalized, flags=re.IGNORECASE))
    if rule_id == 'MOCK_003':
        return bool(re.search(r'(SELECT|INSERT|UPDATE|DELETE)', normalized, flags=re.IGNORECASE)) and '+' in normalized
    if rule_id == 'MOCK_004':
        return 'catch' in normalized and '}' in normalized and normalized.count('{') == normalized.count('}')
    if rule_id == 'MOCK_005':
        return '== null' in normalized or '!= null' in normalized
    if rule_id == 'MOCK_006':
        return 'JSON.parse(JSON.stringify(' in normalized
    if rule_id == 'MOCK_007':
        return 'console.log(' in normalized
    if rule_id == 'MOCK_008':
        return 'TODO' in normalized or 'FIXME' in normalized
    if rule_id == 'MOCK_INJ':
        return bool(re.search(r'(ignore previous instructions|disregard all prior|you are now)', normalized, flags=re.IGNORECASE))

    return False


def content_check(diff_file):
    if not diff_file:
        return []

    findings = []
    for file_entry in diff_file:
        for change in file_entry.get('changes', []):
            if change.get('type') != 'added':
                continue

            change_text = change.get('text', '')
            for rule in (MOCK_001, MOCK_002, MOCK_003, MOCK_004, MOCK_005, MOCK_006, MOCK_007, MOCK_008, MOCK_INJ):
                if _matches_rule(change_text, rule['ruleId']):
                    findings.append(
                        MockFindings(
                            rule,
                            file_entry['path'],
                            change['line'],
                            change_text,
                        )
                    )

    findings.sort(key=lambda item: (item.path, item.line, item.ruleId))
    return findings


def scan_diff_for_mock_findings(diff_text, max_chunk_bytes=64 * 1024):
    if not isinstance(diff_text, str):
        return [], {'chunks': 0}

    normalized_diff = normalize_diff_text(diff_text)
    chunks = chunk_diff_text(normalized_diff, max_chunk_bytes=max_chunk_bytes)

    findings = []
    seen = set()
    for chunk in chunks:
        parsed_files = parse_request_body({'diff': chunk})
        for finding in content_check(parsed_files):
            dedupe_key = (
                finding.ruleId,
                finding.path,
                finding.line,
                finding.evidence,
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(finding)

    findings.sort(key=lambda item: (item.path, item.line, item.ruleId))
    return findings, {'chunks': len(chunks)}