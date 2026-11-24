"""Headless state/cleanup regression tests for the GUI's real transfer pool."""
import hashlib
import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harbor import gui
from harbor.client import Client, ClientError


class LocalTransport:
    """Test transport with real source/partial files and reserved upload state."""
    instances = []
    transactions = {}
    allow_connect = True
    can_upload = True
    can_download = True
    deny_list = False
    fail_upload = False
    fail_download = False
    list_calls = 0

    def __init__(self, config_path):
        self.upload_ticket = None
        self.calls = []
        type(self).instances.append(self)

    def connect(self):
        if not type(self).allow_connect:
            raise ClientError('network unavailable')
        return {'username': 'test', 'tls_version': 'TLSv1.3',
                'can_upload': type(self).can_upload,
                'can_download': type(self).can_download}

    def list_files(self):
        type(self).list_calls += 1
        if type(self).deny_list or not type(self).can_download:
            raise ClientError('listing denied', 'DENIED')
        return []

    def ping(self):
        return {}

    def close(self):
        pass

    def upload(self, source, remote_name=None, progress=None, **kwargs):
        self.upload_ticket = None
        data = Path(source).read_bytes()
        ticket = {'transfer_id': remote_name, 'name': remote_name, 'size': len(data),
                  'sha256': hashlib.sha256(data).hexdigest()}
        self.upload_ticket = ticket
        type(self).transactions[ticket['transfer_id']] = ticket
        self.calls.append(('upload', source))
        progress(1, len(data))
        if type(self).fail_upload:
            raise ClientError('interrupted after begin')
        return {'status': 'paused', 'bytes': 1, 'total': len(data), 'upload_ticket': ticket}

    def cancel_upload(self, ticket):
        self.connect()
        type(self).transactions.pop(ticket['transfer_id'])
        self.calls.append(('cancel_upload', dict(ticket)))
        return {'status': 'cancelled', 'bytes': 0, 'total': ticket['size']}

    def download(self, source, target, **kwargs):
        Path(str(target) + '.part').write_bytes(b'partial')
        Path(str(target) + '.part.json').write_text('{}')
        if type(self).fail_download:
            raise ClientError('interrupted download')
        return {'status': 'paused', 'bytes': 7, 'total': 20}

    def cancel_download(self, target):
        for suffix in ('.part', '.part.json'):
            Path(str(target) + suffix).unlink(missing_ok=True)
        self.calls.append(('cancel_download', str(target)))
        return {'status': 'cancelled', 'bytes': 0, 'total': 0}


class GuiPoolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.folder = Path(self.directory.name)
        LocalTransport.instances = []
        LocalTransport.transactions = {}
        LocalTransport.allow_connect = True
        LocalTransport.can_upload = True
        LocalTransport.can_download = True
        LocalTransport.deny_list = False
        LocalTransport.fail_upload = False
        LocalTransport.fail_download = False
        LocalTransport.list_calls = 0
        self.patch = patch.object(gui, 'Client', LocalTransport)
        self.patch.start()
        self.pools = []

    def tearDown(self):
        for pool in self.pools:
            pool.close()
        self.patch.stop()
        self.directory.cleanup()

    def pool(self, workers=1):
        pool = gui.TransferPool('test-transport', workers=workers)
        self.pools.append(pool)
        pool.start()
        return pool

    def wait(self, predicate):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.005)
        self.fail('Timed out waiting for transfer pool')

    def wait_state(self, pool, job, state):
        self.wait(lambda: pool.snapshot(job)['state'] == state)

    @staticmethod
    def events(pool):
        events = []
        while True:
            try:
                events.append(pool.events.get_nowait())
            except queue.Empty:
                return events

    def test_cancel_paused_upload_after_source_deleted_cleans_reserved_transaction(self):
        pool = self.pool()
        source = self.folder / 'source'
        source.write_bytes(b'original content')
        job = pool.submit('upload', source, 'source')
        self.wait_state(pool, job, 'paused')
        source.unlink()
        pool.cancel(job)
        self.wait_state(pool, job, 'cancelled')
        self.assertEqual(LocalTransport.transactions, {})
        self.assertEqual(sum(call[0] == 'upload' for c in LocalTransport.instances for call in c.calls), 1)

    def test_cancel_failed_upload_uses_ticket_captured_before_error(self):
        LocalTransport.fail_upload = True
        pool = self.pool()
        source = self.folder / 'source'
        source.write_bytes(b'original content')
        job = pool.submit('upload', source, 'source')
        self.wait_state(pool, job, 'error')
        source.write_bytes(b'changed content')
        pool.cancel(job)
        self.wait_state(pool, job, 'cancelled')
        self.assertEqual(LocalTransport.transactions, {})

    def test_cancel_during_pause_response_requeues_ticket_cleanup(self):
        response_ready = threading.Event()
        release_response = threading.Event()
        original = LocalTransport.upload

        def delayed_upload(client, *args, **kwargs):
            result = original(client, *args, **kwargs)
            response_ready.set()
            release_response.wait(2)
            return result

        with patch.object(LocalTransport, 'upload', delayed_upload):
            pool = self.pool()
            source = self.folder / 'source'
            source.write_bytes(b'original content')
            job = pool.submit('upload', source, 'source')
            self.assertTrue(response_ready.wait(2))
            pool.cancel(job)
            release_response.set()
            self.wait_state(pool, job, 'cancelled')
        self.assertEqual(LocalTransport.transactions, {})

    def test_cancel_paused_download_cleans_local_partials_while_offline(self):
        pool = self.pool()
        target = self.folder / 'download'
        job = pool.submit('download', 'remote', target)
        self.wait_state(pool, job, 'paused')
        LocalTransport.allow_connect = False
        pool.cancel(job)
        self.wait_state(pool, job, 'cancelled')
        self.assertFalse(Path(str(target) + '.part').exists())
        self.assertFalse(Path(str(target) + '.part.json').exists())

    def test_cancel_failed_download_does_not_require_connection(self):
        LocalTransport.fail_download = True
        pool = self.pool()
        target = self.folder / 'download'
        job = pool.submit('download', 'remote', target)
        self.wait_state(pool, job, 'error')
        LocalTransport.allow_connect = False
        pool.cancel(job)
        self.wait_state(pool, job, 'cancelled')
        self.assertFalse(Path(str(target) + '.part').exists())

    def test_never_started_queued_cancel_needs_no_worker(self):
        pool = self.pool(workers=0)
        job = pool.submit('upload', self.folder / 'does-not-exist', 'unused')
        pool.cancel(job)
        self.wait_state(pool, job, 'cancelled')
        self.assertEqual(LocalTransport.transactions, {})

    def test_real_upload_source_open_failure_can_be_cancelled_without_ticket(self):
        class SourceOpeningClient(Client):
            online = True

            def connect(self):
                if not type(self).online:
                    raise ClientError('offline')
                return {'can_upload': True, 'can_download': False}

            def ping(self):
                return {}

        config = self.folder / 'client.json'
        config.write_text('{}')
        with patch.object(gui, 'Client', SourceOpeningClient):
            pool = gui.TransferPool(config, workers=1)
            self.pools.append(pool)
            pool.start()
            job = pool.submit('upload', self.folder / 'missing-source', 'missing-source')
            self.wait_state(pool, job, 'error')
            self.assertIn('missing-source', pool.snapshot(job)['message'])
            SourceOpeningClient.online = False
            pool.cancel(job)
            self.wait_state(pool, job, 'cancelled')

    def test_existing_download_destination_is_skipped_with_guidance(self):
        existing = self.folder / 'existing.txt'
        existing.write_bytes(b'keep existing data')
        enqueued, warnings, confirmations = [], [], []
        window = gui.HarborWindow.__new__(gui.HarborWindow)
        window._connected = window._can_download = True
        window.root = object()
        window.local_folder = SimpleNamespace(get=lambda: str(self.folder))
        window.remote_tree = SimpleNamespace(selection=lambda: ['existing', 'new'])
        window._remote_files = {'existing': {'name': 'existing.txt', 'size': 20},
                                'new': {'name': 'new.txt', 'size': 7}}
        window.pool = SimpleNamespace(submit=lambda *args: enqueued.append(args))
        dialogs = SimpleNamespace(
            showerror=lambda *args, **kwargs: warnings.append(args),
            askyesno=lambda *args, **kwargs: confirmations.append(args) or True)
        with patch.object(gui, 'messagebox', dialogs, create=True):
            window._download_selected()
        self.assertEqual([args[1] for args in enqueued], ['new.txt'])
        self.assertTrue(warnings)
        self.assertEqual(confirmations, [])
        self.assertEqual(existing.read_bytes(), b'keep existing data')

    def test_upload_only_account_connects_without_listing(self):
        LocalTransport.can_download = False
        pool = self.pool(workers=0)
        received = []
        self.wait(lambda: (received.extend(self.events(pool)) or any(e[0] == 'connected' for e in received)))
        pool.refresh()
        time.sleep(.03)
        received.extend(self.events(pool))
        self.assertEqual(LocalTransport.list_calls, 0)
        self.assertFalse(any(event[0] == 'connection_error' for event in received))

    def test_list_denied_does_not_invalidate_authenticated_connection(self):
        LocalTransport.deny_list = True
        pool = self.pool(workers=0)
        received = []
        self.wait(lambda: (received.extend(self.events(pool)) or any(e[0] in ('connection_error', 'list_error') for e in received)))
        self.assertTrue(any(event[0] == 'connected' for event in received))
        self.assertTrue(any(event[0] == 'list_error' for event in received))
        self.assertFalse(any(event[0] == 'connection_error' for event in received))

    def test_connected_event_applies_account_permissions_to_controls(self):
        class Widget:
            def configure(self, **options):
                self.options = options

            def set(self, value):
                self.value = value

        for can_upload, can_download in ((True, False), (False, True)):
            window = gui.HarborWindow.__new__(gui.HarborWindow)
            window._closing = False
            window.worker_count = 4
            window.root = SimpleNamespace(after=lambda *args: 1)
            window.pool = SimpleNamespace(events=queue.Queue())
            for name in ('connection_text', 'identity_text', 'connect_button',
                         'upload_selected', 'upload_files', 'refresh_button',
                         'download_button', 'summary_text'):
                setattr(window, name, Widget())
            window.pool.events.put(('connected', {'can_upload': can_upload,
                                                  'can_download': can_download}))
            window._poll()
            self.assertTrue(window._connected)
            for button in (window.upload_selected, window.upload_files):
                self.assertEqual(button.options['state'], 'normal' if can_upload else 'disabled')
            for button in (window.refresh_button, window.download_button):
                self.assertEqual(button.options['state'], 'normal' if can_download else 'disabled')


if __name__ == '__main__':
    unittest.main()
