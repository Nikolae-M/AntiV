# configuracoes centrais do AntiV (caminhos, limites e ajustes de desempenho)

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SIGNATURES_FILE = DATA_DIR / "signatures.json"
RULES_FILE = DATA_DIR / "rules.json"
HASH_LISTS_DIR = DATA_DIR / "hashes"
CACHE_FILE = DATA_DIR / "cache.sqlite"
QUARANTINE_DIR = BASE_DIR / "quarantine"
QUARANTINE_INDEX = QUARANTINE_DIR / "index.json"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

QUARANTINE_EXT = ".quar"   # extensao inofensiva para evitar execucao acidental
XOR_KEY = 0x5A             # ofuscacao simples (NAO e criptografia forte)

KB = 1024
MB = 1024 * KB

# Leitura de arquivos
HEAD_BYTES = 1 * MB          # trecho inicial analisado em arquivos grandes
TAIL_BYTES = 256 * KB        # trecho final analisado em arquivos grandes
FULL_READ_LIMIT = 8 * MB     # ate este tamanho o arquivo inteiro e analisado

# Arquivos compactados (ZIP) analisados em memoria
ARCHIVE_MAX_ENTRIES = 1000
ARCHIVE_MAX_MEMBER = 32 * MB
ARCHIVE_MAX_TOTAL = 256 * MB
ARCHIVE_MAX_DEPTH = 2
ARCHIVE_MAX_RATIO = 1000     # protecao contra "zip bomb"

# Pontuacao heuristica
SUSPECT_SCORE = 50           # a partir daqui: "suspeito"
INFO_SCORE = 25              # a partir daqui: "observacao"

# Mude este numero quando as heuristicas mudarem (invalida o cache)
ANALYZER_VERSION = "2"

MODE_LEVELS = {"fast": 1, "full": 2, "deep": 3}

# Pastas do sistema que o Windows protege (acesso sempre negado)
EXCLUDED_DIRS = {
    "system volume information", "$recycle.bin",
    "$windows.~bt", "$windows.~ws",
}

# marcador do arquivo de teste inofensivo do AntiV. Montado em tempo de
# execucao para que o proprio codigo-fonte nao contenha o texto completo
TEST_MARKER = bytes.fromhex("414e5449562d544553542d5349474e41545552452d444f2d4e4f542d50414e4943").decode("ascii")

# EDR / monitoramento comportamental
BEHAVIOR_RULES_FILE = DATA_DIR / "behavior_rules.json"
ALLOWLIST_FILE = DATA_DIR / "allowlist.json"
CANARY_FILE = DATA_DIR / "canaries.json"
PERSIST_BASELINE = DATA_DIR / "persistence_baseline.json"
TELEMETRY_FILE = LOGS_DIR / "telemetry.jsonl"
INCIDENTS_DIR = BASE_DIR / "incidents"

# texto inofensivo que dispara o alerta de teste do monitor comportamental
BEHAVIOR_TEST_TOKEN = "ANTIV-BEHAVIOR-TEST"
