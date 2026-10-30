"""Offline checks shared by source tests and the packaged executable."""
import contextlib
import io
import json
import queue
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock


@contextlib.contextmanager
def isolated_paths(ng):
    with tempfile.TemporaryDirectory(prefix='network-guard-check-') as temp:
        base = Path(temp)
        replacements = {'BASE_DIR': base, 'DATA_DIR': base/'data', 'REPORT_DIR': base/'reports', 'CONFIG_PATH': base/'config.json', 'EVENT_LOG': base/'data/events.jsonl', 'SAMPLE_LOG': base/'data/samples.csv'}
        with contextlib.ExitStack() as stack:
            for name, value in replacements.items():
                stack.enter_context(mock.patch.object(ng, name, value))
            yield base


def make_suite(ng):
    class CoreChecks(unittest.TestCase):
        def setUp(self):
            self.paths = isolated_paths(ng)
            self.paths.__enter__()
            self.addCleanup(self.paths.__exit__, None, None, None)
            self.cfg = dict(ng.DEFAULT_CONFIG)
            self.engine = ng.MonitorEngine(self.cfg, queue.Queue())

        def test_russian_and_english_ping(self):
            for text, latency in [('Ответ от 127.0.0.1: число байт=32 время<1мс TTL=128', 0.5), ('Reply from 127.0.0.1: bytes=32 time=13.5ms TTL=128', 13.5)]:
                with self.subTest(text=text), mock.patch.object(ng, 'run_hidden', return_value=(0, text, '')):
                    ok, actual, _ = ng.ping('127.0.0.1', 1000)
                    self.assertTrue(ok)
                    self.assertEqual(actual, latency)

        @unittest.skipUnless(sys.platform == 'win32', 'Windows exit-code behavior')
        def test_unreachable_reply_is_not_success(self):
            with mock.patch.object(ng, 'run_hidden', return_value=(0, 'Reply from 192.0.2.1: Destination host unreachable.', '')):
                self.assertFalse(ng.ping('192.0.2.10', 1000)[0])

        @unittest.skipUnless(sys.platform == 'win32', 'Windows OEM encoding')
        def test_oem_console_text(self):
            text = 'Ответ: время=12мс'
            with mock.patch('ctypes.windll.kernel32.GetOEMCP', return_value=866):
                self.assertEqual(ng._decode_console(text.encode('cp866')), text)

        def test_diagnostic_cases(self):
            baseline = dict(gateway='192.0.2.1', gw_ok=True, public_ok=True, dns_ok=True, tcp_ok=True, http_ok=True, loss=0, public_ms=12)
            self.engine.public_hist.extend([True]*6)
            cases = [('OK', {}), ('LOCAL_ROUTE', {'gateway':''}), ('ICMP_BLOCKED', {'gw_ok':False, 'public_ok':False}), ('DNS', {'dns_ok':False}), ('HTTP_TLS_PROXY', {'http_ok':False}), ('ISP_OR_UPSTREAM', {'public_ok':False, 'tcp_ok':False, 'http_ok':False}), ('HIGH_LATENCY', {'public_ms':200}), ('PACKET_LOSS', {'loss':30})]
            for expected, override in cases:
                with self.subTest(expected=expected):
                    self.assertEqual(self.engine._diagnose(**(baseline | override))[1], expected)
            self.engine.wifi = {'signal':20}
            self.assertEqual(self.engine._diagnose(**(baseline | {'gw_ok':False, 'public_ok':False, 'http_ok':False}))[1], 'WIFI_OR_ROUTER')

        def test_incident_unknown_and_recovery(self):
            bad = ng.Snapshot(ng.now_iso(), 'АВАРИЯ', 'DNS', '<script>alert(1)</script>', 'высокая')
            self.engine._handle_trigger(bad)
            self.assertIsNone(self.engine.current_incident)
            self.engine._handle_trigger(bad)
            self.assertIsNotNone(self.engine.current_incident)
            unknown = ng.Snapshot(ng.now_iso(), 'НЕОПРЕДЕЛЕНО', 'UNKNOWN', 'Mixed checks', 'низкая')
            self.engine._handle_trigger(unknown)
            self.assertIsNotNone(self.engine.current_incident)
            good = ng.Snapshot(ng.now_iso(), 'НОРМА', 'OK', 'Connected', 'высокая')
            self.engine._write_sample(good)
            self.engine._handle_trigger(good)
            self.assertIsNone(self.engine.current_incident)
            kinds = [e['kind'] for e in ng.read_events()]
            self.assertEqual(kinds.count('incident_started'), 1)
            self.assertEqual(kinds.count('incident_recovered'), 1)
            report = next(ng.REPORT_DIR.glob('*.html')).read_text(encoding='utf-8')
            self.assertNotIn('<script>alert(1)</script>', report)
            self.assertIn('&lt;script&gt;', report)

        def test_samples_and_rotation(self):
            snap = ng.Snapshot(ng.now_iso(), 'НОРМА', 'OK', 'Connected', 'высокая')
            self.engine._write_sample(snap)
            self.engine._write_sample(snap)
            self.assertEqual(len(ng.read_recent_samples()), 2)
            ng.EVENT_LOG.write_text('original', encoding='utf-8')
            old = ng.EVENT_LOG.with_suffix('.jsonl.1')
            old.write_text('older', encoding='utf-8')
            self.engine._rotate_if_needed(ng.EVENT_LOG, 3)
            self.assertEqual(old.read_text(encoding='utf-8'), 'original')
            self.assertFalse(ng.EVENT_LOG.exists())

        def test_default_configuration(self):
            self.assertEqual(ng.load_config(), ng.DEFAULT_CONFIG)
            self.assertEqual(json.loads(ng.CONFIG_PATH.read_text(encoding='utf-8')), ng.DEFAULT_CONFIG)
    return unittest.defaultTestLoader.loadTestsFromTestCase(CoreChecks)


def run_checks(ng):
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=1).run(make_suite(ng))
    if not result.wasSuccessful():
        raise RuntimeError(output.getvalue())
    with isolated_paths(ng):
        cfg = dict(ng.DEFAULT_CONFIG, start_monitoring_on_launch=False)
        root = ng.Tk()
        root.withdraw()
        try:
            with mock.patch.object(ng, 'load_config', return_value=cfg):
                app = ng.App(root)
            root.update_idletasks()
            assert app.engine.thread is None
            sample = ng.Snapshot(ng.now_iso(), 'НОРМА', 'OK', 'Synthetic connection', 'высокая')
            app.update_snapshot(asdict(sample))
            root.update_idletasks()
            assert len(app.card_vars) == 6
            app.engine.stop()
        finally:
            root.destroy()
    return {'ok': True, 'tests_passed':result.testsRun, 'gui_created_without_monitoring':True, 'private_data_read':False, 'live_network_probes':False, 'python':sys.version}
