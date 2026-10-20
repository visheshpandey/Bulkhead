# Security

`AgentAction` is descriptive data. Bulkhead does not execute the described
tool call, read a host file, run shell commands, or perform network/GitHub
actions. HoneyWorld uses fake data and no-op external actions.

For shared access, configure `BULKHEAD_API_KEY` and an authenticated TLS
reverse proxy. The built-in shared key applies to evaluation; it is not a
general identity or authorization system for all endpoints. Protect the
SQLite file and WAL files, which can contain action descriptions and findings.
Public-demo sessions and rate limits are process-local and are not production
multi-tenant storage.

Keep real secrets, private keys, cookies, personal data, and production targets
out of fixtures, requests, logs, screenshots, and commits. `.env` and `data/`
are Git-ignored. Report vulnerabilities privately to the repository
maintainers via the contact method on the project homepage, using a synthetic
reproduction.
