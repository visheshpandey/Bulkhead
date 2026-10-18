# Keep the process-global API gateway ephemeral during tests. Production defaults
# to ./data/bulkhead.db when this variable is not set.
__import__("os").environ.setdefault("BULKHEAD_DB_PATH", ":memory:")
