# Submission Summary

## Architecture
The service is a small single-process Python HTTP server that accepts review requests, stores jobs in memory, and routes them through a provider abstraction. The mock provider performs deterministic rule scanning over unified diff content. Using different classes for general jobs. Left a majority of logic in main because its the location that makes the most sense to me

## Provider design
The current implementation keeps the provider boundary explicit. Mock has its own module, llm has its own module using hard codded API calls, I am currently unaware of how to implement it without hard-coding

## Verification
verified chunking by checking code level logic, verified caching by executing code and receiving the same output for  the same job under a different key, verified idempotency by running multiple runs with different idempotency keys and bodies, and same idempotency key but different body. SSE was tested by running, however, I felt like i was at an impasse so I left it alone.

## AI tools used
I used VS Code workspace tools and the Python environment configuration helpers to inspect, refine, and verify the service implementation.

## AI suggestion rejected
I rejected changes that I the structure that felt unorganized to me

## Next steps with more time
allowing users to view job streams, I am currently not certain on how to do it so I left it out
