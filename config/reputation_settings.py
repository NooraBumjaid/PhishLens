"""Central settings for optional external reputation lookups."""

from config.security import MAX_VT_RESPONSE_BYTES, READ_TIMEOUT, TRUE_VALUES

PROVIDER_NAME = "VirusTotal"
VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_TIMEOUT_SECONDS = READ_TIMEOUT
VIRUSTOTAL_MAX_RESPONSE_BYTES = MAX_VT_RESPONSE_BYTES
# Alias kept for readability at the call site.
ENABLED_VALUES = TRUE_VALUES

ALLOWED_TARGET_TYPES = frozenset({"submitted_url", "final_url"})
