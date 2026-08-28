from __future__ import annotations

PRODUCT_REPOSITORY = "Dsamofalov/hwm_predictor"
SUPPLY_CHAIN_SCHEMA = "hwm-graphify-supply-chain/v2"
SUPPLY_CHAIN_BLOB_SHA = "f42132a2f52d1d7af84155a56a86fca2fe4d8605"
UPSTREAM_REPOSITORY = "Graphify-Labs/graphify"
UPSTREAM_TAG = "v0.9.38"
UPSTREAM_COMMIT = "10ad921b423b767dd8a947bbf0fbcc2e95038ad3"
UPSTREAM_UV_LOCK_BLOB_SHA = "8573a9e9d6a4b681c469b9e25a70e309e7da53f3"

GRAPHIFY_PACKAGE = "graphifyy"
GRAPHIFY_VERSION = "0.9.38"
GRAPHIFY_WHEEL = "graphifyy-0.9.38-py3-none-any.whl"
GRAPHIFY_WHEEL_SHA256 = "1335aa0805565279208a47059f8cb0994970ec3dd2155d753d12da425b9d7ee5"
GRAPHIFY_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/ff/88/"
    "c7e94136303275808bffc983394b03e727ab93f900e6a15ca4ba3915dea7/"
    + GRAPHIFY_WHEEL
)
FORBIDDEN_GRAPHIFY_SDIST = "graphifyy-0.9.38.tar.gz"
FORBIDDEN_GRAPHIFY_SDIST_SHA256 = "ec2f5ee490156c249f2fd5af7ea11d5ac95f7ee8155ac5889fa78709abd83c3c"

RUNTIME_IMPLEMENTATION = "CPython"
RUNTIME_VERSION = "3.12.10"
RUNTIME_PLATFORM = "linux-x86_64"
RUNNER_CLASS = "GitHub-hosted disposable"

EXACT_GRAPHIFY_COMMAND = (
    "python", "-m", "graphify", "extract", ".",
    "--code-only", "--no-cluster", "--no-viz",
)
BUILDER_TIMEOUT_SECONDS = 900
TIMEOUT_CLOCK = "monotonic"
TIMEOUT_START_BOUNDARY = "verified-wheelhouse-ready, network-denied, read-only-exact-source-ready"
TIMEOUT_END_BOUNDARY = "canonical-artifact-emission-complete"
TIMEOUT_SCOPE = (
    "offline-installation",
    "exact-structural-graphify-invocation",
    "output-parsing",
    "normalization",
    "schema-validation",
    "digest-calculation",
    "canonical-artifact-emission",
)
TIMEOUT_HEALTH_STATE = "timeout_incomplete_build"
MAX_SNAPSHOT_BYTES = 67108864

PROVIDER_ENVIRONMENT_DENY = (
    "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
    "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "DATABASE_URL", "DEEPSEEK_API_KEY", "FALKORDB_HOST", "FALKORDB_PASSWORD",
    "FALKORDB_PORT", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
    "MOONSHOT_API_KEY", "NEO4J_PASSWORD", "NEO4J_URI", "NEO4J_USERNAME", "OLLAMA_HOST",
    "OPENAI_API_KEY", "OPENAI_BASE_URL", "PGDATABASE", "PGHOST", "PGPASSWORD", "PGPORT",
    "PGUSER",
)
# Additional credential-bearing variables denied by the implementation. This does not alter the
# authoritative provider_environment_deny list above; it narrows the runtime further.
ADDITIONAL_CREDENTIAL_ENV_DENY = (
    "GH_TOKEN", "GITHUB_TOKEN", "GIT_ASKPASS", "SSH_AUTH_SOCK", "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
)

ALLOWED_PACKAGE_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})
FORBIDDEN_OPTIONAL_CAPABILITIES = frozenset({
    "all", "anthropic", "bedrock", "falkordb", "gemini", "google", "kimi", "mcp",
    "neo4j", "ollama", "openai", "postgres", "video", "pdf", "office", "svg", "watch",
    "leiden", "chinese", "sql", "pascal", "dm", "terraform",
})

SNAPSHOT_SCHEMA_BLOB_SHA = "5f96d6bf7da37a08b975cbedc1feccdbfe1ace12"
METADATA_SCHEMA_BLOB_SHA = "dee33775e362d48a6a7fa5cd34b0660aceeea679"
HEALTH_SCHEMA_BLOB_SHA = "b3495ee2ddab379330625ee06e5377fc8d7105d8"
QUERY_SCHEMA_BLOB_SHA = "5ac42a42e8f51a0dc3c250e472e4c23ae5b6f5c4"
CANONICALIZATION = "hwm-graph-canonical/v1"
TIMEOUT_USABLE = False
TIMEOUT_PROCESS_TREE_POLICY = "terminate"
PARTIAL_OUTPUT_POLICY = "discard"
TIMEOUT_PARTIAL_SNAPSHOT_METADATA_POLICY = "reject"
TIMEOUT_PARTIAL_CANONICAL_ARTIFACT_POLICY = "delete"
TIMEOUT_SNAPSHOT_IDENTITY = None
TIMEOUT_PUBLICATION_POLICY = "forbidden"
TIMEOUT_CONSUMER_FALLBACK = "deterministic-raw-source"
RETRY_POLICY = "clean-disposable-reexecution-only"
RETRY_PARTIAL_OUTPUT_REUSE = "forbidden"
RETRY_EXACT_INPUTS_POLICY = "same-exact-inputs"
TIMEOUT_CHANGE_POLICY = "new-versioned-contract-amendment-required"
GITHUB_ACTIONS_JOB_CONTAINMENT_POLICY = (
    "may-exceed-900-seconds-only-to-record-fail-closed-health-result; semantic-builder-timeout-remains-900-seconds"
)
