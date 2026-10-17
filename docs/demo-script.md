# First demo script

1. Start AIRLOCK locally.
2. Show a normal `read_file` action being allowed.
3. Submit a malicious webpage event that asks the agent to read `.env`.
4. Show the action being blocked and quarantined.
5. Route the suspicious action into HoneyWorld with fake credentials.
6. Display the Black Box timeline and generated immunity rule.
7. Re-run the same attack and show the new regression rule blocking it immediately.
