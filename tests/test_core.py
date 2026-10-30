import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import network_guard
from smoke_checks import make_suite

def load_tests(loader, tests, pattern):
    return make_suite(network_guard)
