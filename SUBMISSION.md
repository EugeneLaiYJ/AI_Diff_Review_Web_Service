# Submission Summary

## Architecture
The service is a small single-process Python HTTP server that accepts review requests, stores jobs in memory, and routes them through a provider abstraction. The mock provider performs deterministic rule scanning over unified diff content. Using different classes for general jobs. Left a majority of logic in main because its the location that makes the most sense to me

## Provider design
The current implementation keeps the provider boundary explicit. Mock has its own module, llm has its own module using hard codded API calls, I am currently unawsare of how to implement it without hard-coding

## Verification
I verified the current code path with compilation plus targeted unit coverage. The regression tests cover chunking behavior and the idempotency key + body-hash requirement. The current verification command is:

`C:/Users/myUsername/AppData/Local/Python/pythoncore-3.14-64/python.exe -m py_compile main.py jobStore.py llmProvider.py diffParser.py mockProvider.py && C:/Users/myUsername/AppData/Local/Python/pythoncore-3.14-64/python.exe -m unittest discover -s tests -v`

This completed successfully with 3 passing tests.

## AI tools used
I used VS Code workspace tools and the Python environment configuration helpers to inspect, refine, and verify the service implementation.

## AI suggestion rejected
I rejected a larger rewrite to a full async framework because the existing project already has a compact socket/service shape and the scoring bar here is mostly about contract behavior and deterministic provider output, not framework purity.

## Next steps with more time
allowing users to view job streams, I am currently not certain on how to do it so I left it out
