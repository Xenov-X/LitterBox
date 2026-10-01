# EDR-integration analyzers — pluggable backend architecture.
#
# Dispatches payloads to a Whiskers agent on a user-managed VM, then
# resolves alerts via the profile's registered backend:
#   * kind: elastic  — queries an Elastic Detection-Engine cluster.
#   * kind: fibratus — polls Whiskers's /api/alerts/fibratus/since.
#   * kind: exec     — execution-only, no detection backend.
#   * (third-party)  — drop a module in backends/ or install a
#                      litterbox.edr_backends entry-point.
#
# See Config/edr_profiles/*.yml.example for the per-kind schema.
