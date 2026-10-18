# Keep the process-global API gateway ephemeral during tests. Production defaults
# to ./data/airlock.db when this variable is not set.
__import__("os").environ.setdefault("AIRLOCK_DB_PATH", ":memory:")
