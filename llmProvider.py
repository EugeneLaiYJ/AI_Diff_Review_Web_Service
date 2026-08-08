from __future__ import annotations
import os
try:
    from openai import OpenAI
except Exception:
    OpenAI = None

from diffParser import *


def _openai_client():
    api_key = os.getenv('OPENAI_API_KEY','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')
    if not api_key or OpenAI is None:
        return None
    return OpenAI(api_key=api_key)


def create_llm_findings(diff_text, options=None, max_findings=100):
    print("LLM helper called")
    if not diff_text:
        print("No diff text provided; returning placeholder findings.")
        return {
            'findings': [],
            'usage': {
                'inputBytes': 0,
                'chunks': 1,
                'cacheHit': False,
                'provider': 'llm',
                'placeholder': True,
                'maxFindings': max_findings,
            }
        }

    if isinstance(diff_text, str) and '\n' not in diff_text and os.path.exists(diff_text):
        with open(diff_text, encoding='utf-8') as fin:
            diff_text = fin.read()

    print("LLM prompt prepared")

    client = _openai_client()
    if client is None:
        print("OpenAI API key is missing; returning placeholder findings.")
        return {
            'findings': [],
            'usage': {
                'inputBytes': len(diff_text.encode('utf-8')),
                'chunks': 1,
                'cacheHit': False,
                'provider': 'llm',
                'placeholder': True,
                'maxFindings': max_findings,
            },
        }

    print("Sending request to OpenAI")
    try:
        # Determine an explicit output token budget for the model call.
        # Respect an explicit `options['maxOutputTokens']` when present;
        # otherwise derive a conservative default from `max_findings`.
        tokens_per_finding = 32
        if isinstance(options, dict) and options.get('maxOutputTokens'):
            requested_output_tokens = int(options.get('maxOutputTokens'))
        else:
            requested_output_tokens = tokens_per_finding * (max_findings or 100)
            # clamp to a reasonable upper/lower bound
            requested_output_tokens = max(64, min(4096, requested_output_tokens))

        response = client.responses.create(
            model='gpt-5.6-luna',
            input='Create findings based on the following unidiff:\n' + diff_text,
            reasoning={'effort': 'low'},
            max_output_tokens=requested_output_tokens,
        )
        print("OpenAI request sent")

        # The LLM output may be empty; coerce to string and split into lines.
        raw_output = getattr(response, 'output_text', '') or ''
        all_lines = [ln for ln in raw_output.splitlines() if ln.strip()]

        # Try to parse each line as JSON finding, otherwise wrap as a minimal finding dict.
        parsed_findings = []
        for ln in all_lines:
            parsed = None
            try:
                import json as _json

                candidate = _json.loads(ln)
                if isinstance(candidate, dict) and 'id' in candidate and 'path' in candidate:
                    parsed = candidate
            except Exception:
                parsed = None

            if parsed is None:
                # Create a conservative structured finding from free text.
                fid = f"LLM-{abs(hash(ln)) % (10 ** 8)}"
                parsed = {
                    'id': f"{fid}:unknown:0",
                    'ruleId': fid,
                    'path': 'unknown',
                    'line': 0,
                    'severity': 'low',
                    'category': 'style',
                    'title': (ln[:120] + '...') if len(ln) > 123 else ln,
                    'evidence': ln,
                }

            parsed_findings.append(parsed)

        # Enforce max_findings limit (entry limiter)
        limited_findings = parsed_findings[:max_findings] if max_findings is not None else parsed_findings

        return {
            'findings': limited_findings,
            'usage': {
                'inputBytes': len(diff_text.encode('utf-8')),
                'chunks': 1,
                'cacheHit': False,
                'provider': 'llm',
                'returnedFindings': len(parsed_findings),
                'maxFindings': max_findings,
                'requestedOutputTokens': requested_output_tokens,
            },
        }
    except Exception as exc:
        print(f"OpenAI request failed: {type(exc).__name__}: {exc}")
        raise

def scan_diff_for_llm_findings(diff_text, max_chunk_bytes=64 * 1024, max_findings=100):
    if not isinstance(diff_text, str):
        return [], {'chunks': 0}

    normalized_diff = normalize_diff_text(diff_text)
    chunks = chunk_diff_text(normalized_diff, max_chunk_bytes=max_chunk_bytes)

    all_findings = []
    seen_ids = set()
    remaining = max_findings if max_findings is not None else None
    total_reported = 0

    for chunk in chunks:
        if remaining == 0:
            break
        resp = create_llm_findings(chunk, options=None, max_findings=remaining if remaining is not None else None)
        chunk_findings = resp.get('findings', []) if isinstance(resp, dict) else list(resp)

        for f in chunk_findings:
            fid = f.get('id') if isinstance(f, dict) else str(f)
            if fid in seen_ids:
                continue
            seen_ids.add(fid)
            all_findings.append(f)
            total_reported += 1
            if remaining is not None:
                remaining = max(0, remaining - 1)
                if remaining == 0:
                    break

    # Sort findings by path, line, ruleId (lexicographic for path and ruleId)
    def _sort_key(f):
        try:
            return (f.get('path', ''), int(f.get('line', 0)), f.get('ruleId', ''))
        except Exception:
            return (f.get('path', ''), 0, f.get('ruleId', ''))

    all_findings.sort(key=_sort_key)

    # Final trim to max_findings in case of any mismatch
    if max_findings is not None:
        all_findings = all_findings[:max_findings]

    usage = {
        'chunks': len(chunks),
        'cacheHit': False,
        'provider': 'llm',
        'maxFindings': max_findings,
        'reportedFindings': total_reported,
    }
    return all_findings, usage