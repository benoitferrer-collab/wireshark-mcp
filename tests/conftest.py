"""
Configuration pytest et fixtures
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Ajouter le chemin du projet
sys.path.insert(0, str(Path(__file__).parent.parent))

# ---------------------------------------------------------------------------
# Stub out heavy / infrastructure-only modules so that unit tests can import
# app.api.routes (and extract_osi_layers) without a running Docker stack.
# ---------------------------------------------------------------------------
_STUB_MODULES = [
    # Celery / Redis
    "celery", "celery.result",
    # App core infrastructure
    "app.core.celery_app",
    "app.core.logging_config",
    # App services
    "app.services.pcap_service",
    "app.services.timeline_service",
    "app.services.graph_service",
    "app.services.stream_service",
    "app.services.enrichment_service",
    "app.services.ai_analysis_service",
    # Report generators
    "app.reports",
    "app.reports.json_report",
    "app.reports.csv_report",
    "app.reports.pdf_report",
]

for _mod in _STUB_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# Provide concrete attributes referenced at module import time in routes.py
sys.modules["celery.result"].AsyncResult = MagicMock
sys.modules["app.core.celery_app"].celery_app = MagicMock()
sys.modules["app.core.logging_config"].get_logger = lambda name=None: MagicMock()
sys.modules["app.services.pcap_service"].analyze_pcap_task = MagicMock()
sys.modules["app.services.timeline_service"].get_timeline_service = MagicMock()
sys.modules["app.services.graph_service"].get_graph_service = MagicMock()
sys.modules["app.services.stream_service"].get_stream_service = MagicMock()
sys.modules["app.services.enrichment_service"].get_enrichment_service = MagicMock()
sys.modules["app.services.ai_analysis_service"].ai_service = MagicMock()
sys.modules["app.reports.json_report"].JSONReportGenerator = MagicMock
sys.modules["app.reports.csv_report"].CSVReportGenerator = MagicMock
sys.modules["app.reports.pdf_report"].PDFReportGenerator = MagicMock

# Also stub app.core.config so mkdir('/app/...') is never called
import types as _types
_config_mod = _types.ModuleType("app.core.config")
_settings = MagicMock()
_settings.upload_dir = Path("/tmp/pcap_test_uploads")
_settings.results_dir = Path("/tmp/pcap_test_results")
_config_mod.settings = _settings
_config_mod.get_settings = lambda: _settings
sys.modules["app.core.config"] = _config_mod


@pytest.fixture
def sample_pcap_path():
    """Retourne le chemin du fichier PCAP de test"""
    return Path(__file__).parent / 'test_sample.pcap'


@pytest.fixture
def temp_results_dir(tmp_path):
    """Crée un répertoire temporaire pour les résultats"""
    results_dir = tmp_path / 'results'
    results_dir.mkdir()
    return results_dir
