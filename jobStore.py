import hashlib
import json
import queue
import threading

from llmProvider import scan_diff_for_llm_findings
from mockProvider import scan_diff_for_mock_findings


def _normalize_request_value(value):
    if isinstance(value, dict):
        return {key: _normalize_request_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_normalize_request_value(item) for item in value]
    return value


def build_body_hash(diff_text, options=None):
    request_payload = {
        'diff': diff_text.strip() if isinstance(diff_text, str) else '',
        'options': _normalize_request_value(options or {}),
    }
    serialized_payload = json.dumps(
        request_payload,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized_payload.encode('utf-8')).hexdigest()


class Job:
    def __init__(self, job_id, status, findings, usage, idempotency_key, body_text, provider='mock', request_options=None):
        self.job_id = job_id
        self.status = status
        self.findings = findings
        self.usage = usage
        self.idempotency_key = idempotency_key
        self.provider = provider
        self.request_options = _normalize_request_value(request_options or {})
        self.body_text = body_text
        self.body_hash = build_body_hash(body_text, self.request_options)
        self.event_history = []
        self.subscribers = []
        self._subscriber_lock = threading.Lock()
        self.error = None

    def JobResponse(self):
        return {
            'jobId': self.job_id,
            'status': self.status,
            'findings': self.findings,
            'usage': self.usage,
        }

    def add_event(self, event, data):
        event_obj = {'event': event, 'data': data}
        self.event_history.append(event_obj)
        with self._subscriber_lock:
            for subscriber in list(self.subscribers):
                subscriber.put(event_obj)

    def subscribe(self):
        subscriber = queue.Queue()
        with self._subscriber_lock:
            self.subscribers.append(subscriber)
        return subscriber

    def unsubscribe(self, subscriber):
        with self._subscriber_lock:
            if subscriber in self.subscribers:
                self.subscribers.remove(subscriber)

    def close_subscribers(self):
        with self._subscriber_lock:
            for subscriber in list(self.subscribers):
                subscriber.put(None)
            self.subscribers.clear()


def is_idempotency_exist(job_a, job_b):
    return bool(
        isinstance(job_a, Job)
        and isinstance(job_b, Job)
        and job_a.idempotency_key == job_b.idempotency_key
        and job_a.body_hash == job_b.body_hash
    )


def create_findings(diff_text, provider='mock', max_findings=100, event_callback=None):
    normalized_provider = str(provider).lower()
    print(f"create_findings: provider={normalized_provider}, max_findings={max_findings}")
    if normalized_provider == 'llm':
        print('create_findings: dispatching to create_llm_findings')
        findings, usage = scan_diff_for_llm_findings(diff_text, max_findings=max_findings)
        usage['cacheHit'] = False
        usage['provider'] = 'llm'
        usage['maxFindings'] = max_findings
        if event_callback is not None:
            for finding in findings:
                event_callback(finding)
        return {
            'findings': findings,
            'usage': usage,
        }

    findings, usage = scan_diff_for_mock_findings(diff_text)
    usage['cacheHit'] = False
    usage['provider'] = 'mock'
    usage['maxFindings'] = max_findings

    ordered_findings = []
    for finding in findings:
        response = finding.MockResponse()
        if event_callback is not None:
            event_callback(response)
        ordered_findings.append(response)

    return {
        'findings': ordered_findings,
        'usage': usage,
    }

