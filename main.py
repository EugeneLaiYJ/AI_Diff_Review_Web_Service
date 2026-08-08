import json
import os
import re
import socket
import threading
import time
from collections import deque
import queue

from jobStore import Job, create_findings

# Server constants
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 6767
APP_VERSION = '1.0.0'
MAX_REQUEST_BYTES = 1024 * 1024
EXPECTED_BEARER_TOKEN = os.getenv('hehe')


class RuntimeTracker:
    def __init__(self):
        self.started_at = time.time()
        self.total_requests = 0
        self.total_bytes_sent = 0
        self.last_request_at = None
        self.pid = os.getpid()

    def record_request(self):
        self.total_requests += 1
        self.last_request_at = time.time()

    def uptime_seconds(self):
        return int(time.time() - self.started_at)


def parse_http_request(raw_request):
    request_parts = raw_request.split('\r\n\r\n', 1)
    if len(request_parts) != 2:
        return {}, ''

    header_block, body = request_parts
    headers = {}

    lines = header_block.split('\r\n')
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()

    return headers, body


def has_bearer_token(headers, client_socket, expected_token=None):
    auth_header = headers.get('authorization', '')
    parts = auth_header.split()

    if len(parts) != 2 or parts[0].lower() != 'bearer' or not parts[1]:
        send_error_response(client_socket, 'unauthorized', 'Missing or invalid bearer token', 401)
        return False

    provided_token = parts[1]
    if expected_token and provided_token != expected_token:
        send_error_response(client_socket, 'unauthorized', 'Forbidden bearer token', 403)
        return False

    return True


def parse_review_payload(body):
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None, 'invalid_json'

    if not isinstance(payload, dict):
        return None, 'invalid_json'

    diff_text = payload.get('diff')
    if not isinstance(diff_text, str) or not diff_text.strip():
        return None, 'invalid_diff'

    options = payload.get('options') if isinstance(payload.get('options'), dict) else {}
    provider = str(options.get('provider', 'mock')).lower()
    if provider not in {'mock', 'llm'}:
        provider = 'mock'

    if not diff_text.strip().startswith('diff --git '):
        return None, 'invalid_diff'

    return {
        'diff': diff_text,
        'options': options,
        'provider': provider,
    }, None


RATE_LIMIT_PER_MINUTE = 30
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_CONCURRENT_JOBS = 4

submission_timestamps = deque()
job_list_lock = threading.Lock()
job_queue = queue.Queue()


def get_http_status_line(status_code):
    reason_phrases = {
        200: 'OK',
        202: 'Accepted',
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        405: 'Method Not Allowed',
        409: 'Conflict',
        413: 'Payload Too Large',
        415: 'Unsupported Media Type',
        422: 'Unprocessable Entity',
        429: 'Too Many Requests',
        500: 'Internal Server Error',
    }
    return f'HTTP/1.1 {status_code} {reason_phrases.get(status_code, "")}'.strip()


def send_response(client_socket, content, content_type='text/html', status_code=200, extra_headers=None):
    body = content.encode('utf-8')
    status_line = get_http_status_line(status_code)
    header = (
        f'Content-Type: {content_type}\r\n'
        f'Content-Length: {len(body)}\r\n'
    )
    if extra_headers:
        for header_name, header_value in extra_headers.items():
            header += f'{header_name}: {header_value}\r\n'
    header += '\r\n'
    response = status_line + '\r\n' + header + content
    tracker.total_bytes_sent += len(response.encode('utf-8'))
    client_socket.sendall(response.encode('utf-8'))
    client_socket.close()


def send_json_response(client_socket, payload, status_code=200, extra_headers=None):
    send_response(client_socket, json.dumps(payload, indent=4), content_type='application/json', status_code=status_code, extra_headers=extra_headers)


def send_error_response(client_socket, code, message, status_code=400, extra_headers=None):
    payload = {
        'error': {
            'code': code,
            'message': message,
        }
    }
    send_json_response(client_socket, payload, status_code=status_code, extra_headers=extra_headers)


def send_sse_headers(client_socket):
    headers = (
        'HTTP/1.1 200 OK\r\n'
        'Content-Type: text/event-stream\r\n'
        'Cache-Control: no-cache\r\n'
        'Connection: keep-alive\r\n\r\n'
    )
    client_socket.sendall(headers.encode('utf-8'))


def send_sse_event(client_socket, event):
    data = json.dumps(event['data'])
    message = f'event: {event["event"]}\n'
    for line in data.splitlines():
        message += f'data: {line}\n'
    message += '\n'
    client_socket.sendall(message.encode('utf-8'))


def prune_rate_limit():
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    while submission_timestamps and submission_timestamps[0] < cutoff:
        submission_timestamps.popleft()
    return now


def is_rate_limited():
    now = prune_rate_limit()
    if len(submission_timestamps) >= RATE_LIMIT_PER_MINUTE:
        retry_after = int(max(1, RATE_LIMIT_WINDOW_SECONDS - (now - submission_timestamps[0])))
        return True, retry_after
    submission_timestamps.append(now)
    return False, None


def find_job(job_id):
    with job_list_lock:
        return next((item for item in job_list if item.job_id == job_id), None)


def job_worker():
    while True:
        job = job_queue.get()
        if job is None:
            break

        with job_list_lock:
            job.status = 'running'
        job.add_event('status', {'status': 'running'})

        try:
            result = create_findings(
                job.body_text,
                provider=job.provider,
                max_findings=job.request_options.get('maxFindings', 100),
                event_callback=lambda finding: job.add_event('finding', finding),
            )

            with job_list_lock:
                job.findings = result.get('findings', [])
                job.usage = result.get('usage', job.usage)
                job.status = 'done'

            job.add_event('status', {'status': 'done'})
            for finding in job.findings:
                job.add_event('finding', finding)
            job.add_event('done', {'total': len(job.findings), 'usage': job.usage})
        except Exception as exc:
            error_message = str(exc)
            with job_list_lock:
                job.status = 'failed'
                job.error = error_message
            job.add_event('status', {'status': 'failed', 'error': error_message})
            job.add_event('done', {'total': 0, 'usage': job.usage})
        finally:
            job_queue.task_done()


tracker = RuntimeTracker()

# socket creation
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(5)

def handle_client(client_socket, client_address):
    try:
        request = client_socket.recv(MAX_REQUEST_BYTES).decode(errors='ignore')
        if not request:
            client_socket.close()
            return

        headers, body = parse_http_request(request)
        header_lines = request.split('\r\n')
        first_header_component = header_lines[0].split()

        if len(first_header_component) < 2:
            client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            client_socket.close()
            return

        http_method = first_header_component[0]
        path = first_header_component[1]
        tracker.record_request()

        if http_method == 'GET':
            if path == '/health':
                with open('health.json', encoding='utf-8') as fin:
                    content = fin.read()
                content = (
                    content
                    .replace('<status>', 'ok')
                    .replace('<semver>', APP_VERSION)
                    .replace('<Number>', str(tracker.uptime_seconds()))
                )
                send_response(client_socket, content, content_type='application/json')
                return

            if path == '/spec':
                with open('spec.json', encoding='utf-8') as fin:
                    content = fin.read()
                send_response(client_socket, content, content_type='application/json')
                return

            if path.startswith('/v1/reviews/'):
                if EXPECTED_BEARER_TOKEN and not has_bearer_token(headers, client_socket, expected_token=EXPECTED_BEARER_TOKEN):
                    return

                if path == '/v1/reviews/':
                    send_error_response(client_socket, 'not_found', 'Unknown review route', 404)
                    return

                route_match = re.match(r'^/v1/reviews/([^/]+)(?:/stream)?/?$', path)
                if not route_match:
                    send_error_response(client_socket, 'not_found', 'Unknown review route', 404)
                    return

                job_id = route_match.group(1)
                if not job_id:
                    send_error_response(client_socket, 'not_found', 'Unknown job id', 404)
                    return

                is_stream_request = path.rstrip('/').endswith('/stream')
                if is_stream_request:
                    return handle_review_stream(client_socket, job_id)

                job = find_job(job_id)
                if not job:
                    send_error_response(client_socket, 'not_found', 'Unknown job id', 404)
                    return

                send_json_response(client_socket, job.JobResponse(), status_code=200)
                return

            send_response(client_socket, content)
            return

        if http_method == 'POST' and path == '/v1/reviews':
            if not has_bearer_token(headers, client_socket, expected_token=EXPECTED_BEARER_TOKEN):
                return

            rate_limited, retry_after = is_rate_limited()
            if rate_limited:
                send_error_response(
                    client_socket,
                    'rate_limited',
                    'Too many requests',
                    status_code=429,
                    extra_headers={'Retry-After': str(retry_after)},
                )
                return

            content_type = headers.get('content-type', '')
            content_length = int(headers.get('content-length', 0))

            if 'application/json' not in content_type:
                send_error_response(client_socket, 'invalid_json', 'Unsupported Media Type', 415)
                return

            if content_length > MAX_REQUEST_BYTES:
                send_error_response(client_socket, 'payload_too_large', 'Payload Too Large', 413)
                return

            if not body:
                send_error_response(client_socket, 'invalid_json', 'Bad Request', 400)
                return

            payload, error = parse_review_payload(body)
            if error:
                code = 'invalid_json' if error == 'invalid_json' else 'invalid_diff'
                send_error_response(client_socket, code, error.title().replace('_', ' '), 400 if error == 'invalid_json' else 422)
                return

            idempotency_key = headers.get('idempotency-key')
            provider = payload['provider']

            temp_job = Job(
                f'Job-{int(time.time() * 1000)}',
                'queued',
                [],
                {'inputBytes': len(payload['diff'].encode('utf-8')), 'chunks': 1, 'cacheHit': False},
                idempotency_key,
                payload['diff'],
                provider,
                request_options=payload['options'],
            )

            with job_list_lock:
                cached_job = next((job for job in job_list if job.body_hash == temp_job.body_hash), None)
                if cached_job:
                    cached_usage = dict(cached_job.usage)
                    cached_usage['cacheHit'] = True
                    send_json_response(
                        client_socket,
                        {
                            'jobId': cached_job.job_id,
                            'status': cached_job.status,
                            'findings': cached_job.findings,
                            'usage': cached_usage,
                        },
                        status_code=200,
                    )
                    return

                if idempotency_key:
                    conflict_job = next(
                        (job for job in job_list if job.idempotency_key == idempotency_key and job.body_hash != temp_job.body_hash),
                        None,
                    )
                    if conflict_job:
                        send_error_response(client_socket, 'idempotency_conflict', 'Idempotency key already in use with different body', 409)
                        return

                temp_job.job_id = f'Job-{len(job_list) + 1}'
                job_list.append(temp_job)

            temp_job.add_event('status', {'status': 'queued'})
            job_queue.put(temp_job)
            send_json_response(client_socket, {'jobId': temp_job.job_id, 'status': 'queued'}, status_code=202)
            return

        send_error_response(client_socket, 'internal', 'Method Not Allowed', status_code=405)
    except Exception as exc:
        try:
            send_error_response(client_socket, 'internal', str(exc), status_code=500)
        except Exception:
            client_socket.close()


def handle_review_stream(client_socket, job_id):
    job = find_job(job_id)
    if not job:
        send_error_response(client_socket, 'not_found', 'Unknown job id', 404)
        return

    try:
        send_sse_headers(client_socket)
        subscriber = job.subscribe()

        for event in job.event_history:
            send_sse_event(client_socket, event)
            if event['event'] == 'done':
                client_socket.close()
                return

        while True:
            event = subscriber.get()
            if event is None:
                break
            send_sse_event(client_socket, event)
            if event['event'] == 'done':
                break
    except Exception:
        pass
    finally:
        job.unsubscribe(subscriber)
        try:
            client_socket.close()
        except Exception:
            pass


tracker = RuntimeTracker()

# socket creation
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(5)

worker_threads = []
for _ in range(MAX_CONCURRENT_JOBS):
    worker = threading.Thread(target=job_worker, daemon=True)
    worker.start()
    worker_threads.append(worker)

print(f'Listening on port {SERVER_PORT}...')

job_list = []

while True:
    client_socket, client_address = server_socket.accept()
    handler = threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True)
    handler.start()
