"""Native desktop client; worker threads communicate with Tk through a queue."""
from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from .client import Client


def format_bytes(value):
    value = float(value)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(value) < 1024 or unit == 'TiB':
            return ('%d %s' if unit == 'B' else '%.1f %s') % (value, unit)
        value /= 1024


@dataclass
class TransferJob:
    direction: str
    source: str
    target: str
    total: int = 0
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    done: int = 0
    state: str = 'queued'
    speed: float = 0.0
    message: str = ''
    pause_event: threading.Event = field(default_factory=threading.Event)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    active: bool = False
    queued: bool = True
    last_time: float = 0.0
    last_done: int = 0
    last_emit: float = 0.0
    started: bool = False
    upload_ticket: Optional[dict] = None

    def snapshot(self):
        return {key: getattr(self, key) for key in (
            'id', 'direction', 'source', 'target', 'total', 'done',
            'state', 'speed', 'message')}


class TransferPool:
    """One control connection and a bounded set of reusable transfer connections.

    No object in this class accesses Tk. Every event is plain data, consumed by
    the window's main-thread timer. A job retains its identity when resumed.
    """

    def __init__(self, config_path, workers=4):
        self.config_path = str(config_path)
        self.worker_count = workers
        self.events = queue.Queue()
        self._work = queue.Queue()
        self._control = queue.Queue()
        self._jobs: Dict[str, TransferJob] = {}
        self._clients = []
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._started = False

    def start(self):
        if self._started:
            self.reconnect()
            return
        self._started = True
        threading.Thread(target=self._control_loop, name='harbor-control', daemon=True).start()
        for index in range(self.worker_count):
            threading.Thread(target=self._worker_loop, name='harbor-transfer-%d' % (index + 1), daemon=True).start()

    def _new_client(self):
        client = Client(self.config_path)
        with self._lock:
            self._clients.append(client)
        if self._stop.is_set():
            client.close()
            raise RuntimeError('客户端正在关闭')
        return client

    def reconnect(self):
        self._control.put('connect')

    def refresh(self):
        self._control.put('list')

    def submit(self, direction, source, target, total=0):
        if direction not in ('upload', 'download'):
            raise ValueError('未知传输方向')
        if self._stop.is_set():
            raise ValueError('连接池已关闭')
        with self._lock:
            for previous in self._jobs.values():
                if (previous.direction == direction and previous.target == str(target)
                        and previous.state not in ('complete', 'cancelled')):
                    raise ValueError('已有同一目标的未完成任务，请继续或取消原任务')
            job = TransferJob(direction, str(source), str(target), total)
            self._jobs[job.id] = job
            self._emit(job)
            self._work.put(job.id)
            return job.id

    def snapshot(self, job_id):
        with self._lock:
            return self._jobs[job_id].snapshot()

    def pause(self, job_id):
        with self._lock:
            job = self._jobs[job_id]
            if job.state in ('queued', 'running') and not job.cancel_event.is_set():
                job.pause_event.set()
                job.state = 'pausing' if job.active else 'paused'
                job.speed = 0
                self._emit(job)

    def resume(self, job_id):
        with self._lock:
            job = self._jobs[job_id]
            if job.state not in ('paused', 'error') or job.active:
                return
            if job.cancel_event.is_set():
                # A failed cleanup must stay a cancellation when retried.
                job.message = '重新尝试清理临时数据'
            else:
                job.message = ''
            job.pause_event.clear()
            job.state = 'queued'
            job.speed = 0
            if not job.queued:
                job.queued = True
                self._work.put(job.id)
            self._emit(job)

    def cancel(self, job_id):
        with self._lock:
            job = self._jobs[job_id]
            if job.state in ('complete', 'cancelled'):
                return
            job.cancel_event.set()
            job.pause_event.clear()
            if not job.active and job.upload_ticket is None and (
                    not job.started or job.direction == 'upload'):
                job.state = 'cancelled'
                job.message = '已取消；未建立需清理的传输事务'
                self._emit(job)
                return
            job.state = 'cancelling'
            job.message = '正在清理临时数据'
            if not job.active and not job.queued:
                job.queued = True
                self._work.put(job.id)
            self._emit(job)

    def close(self):
        """Signal pause and start connection shutdown without joining on Tk."""
        self._stop.set()
        with self._lock:
            for job in self._jobs.values():
                if job.state not in ('complete', 'cancelled'):
                    job.pause_event.set()
            clients = list(self._clients)
        for client in clients:
            threading.Thread(target=self._close_client, args=(client,), daemon=True).start()

    def _close_client(self, client):
        try:
            client.close()
        except Exception:
            # Closing an already broken transport has no recoverable action.
            pass
        finally:
            with self._lock:
                if client in self._clients:
                    self._clients.remove(client)

    def _emit(self, job):
        self.events.put(('job', job.snapshot()))

    def _control_loop(self):
        client = None
        command = 'connect'
        while not self._stop.is_set():
            try:
                if client is None:
                    client = self._new_client()
                if command == 'connect':
                    info = client.connect()
                    self.events.put(('connected', info))
                    self._control_list(client, info)
                elif command == 'list':
                    info = client.connect()
                    self._control_list(client, info)
                else:
                    client.ping()
            except Exception as exc:
                if not self._stop.is_set():
                    self.events.put(('connection_error', str(exc)))
                if client is not None:
                    self._close_client(client)
                    client = None
            try:
                command = self._control.get(timeout=15)
            except queue.Empty:
                # Only reconnect on user request; avoid repeated certificate errors.
                if client is None:
                    while not self._stop.is_set():
                        try:
                            command = self._control.get(timeout=.25)
                            break
                        except queue.Empty:
                            pass
                else:
                    command = 'ping'
        if client is not None:
            self._close_client(client)

    def _control_list(self, client, info):
        if not info.get('can_download', True):
            self.events.put(('files', []))
            self.events.put(('log', '当前账号仅有上传权限，远端列表不可用。'))
            return
        try:
            self.events.put(('files', client.list_files()))
        except Exception as exc:
            if getattr(exc, 'code', None) != 'DENIED':
                raise
            self.events.put(('list_error', str(exc)))

    def _worker_loop(self):
        client = None
        try:
            client = self._new_client()
            client.connect()
        except Exception as exc:
            if not self._stop.is_set():
                self.events.put(('log', '工作连接建立失败：%s；下个任务会重新验证证书并连接。' % exc))
            if client is not None:
                self._close_client(client)
                client = None
        heartbeat_at = time.monotonic() + 15
        while not self._stop.is_set():
            try:
                job_id = self._work.get(timeout=.25)
            except queue.Empty:
                if client is not None and time.monotonic() >= heartbeat_at:
                    try:
                        client.ping()
                    except Exception as exc:
                        if not self._stop.is_set():
                            self.events.put(('log', '工作连接断开：%s；下个任务会重新验证证书并连接。' % exc))
                        self._close_client(client)
                        client = None
                    heartbeat_at = time.monotonic() + 15
                continue
            with self._lock:
                job = self._jobs[job_id]
                job.queued = False
                if job.state in ('complete', 'cancelled'):
                    continue
                if job.pause_event.is_set() and not job.cancel_event.is_set():
                    job.state = 'paused'
                    self._emit(job)
                    continue
                job.active = True
                job.state = 'cancelling' if job.cancel_event.is_set() else 'running'
                job.last_time = time.monotonic()
                job.last_done = job.done
                job.last_emit = 0
                self._emit(job)
            upload_started = False
            try:
                if client is None:
                    client = self._new_client()

                def progress(done, total):
                    now = time.monotonic()
                    with self._lock:
                        job.done, job.total = done, total
                        if job.direction == 'upload':
                            ticket = getattr(client, 'upload_ticket', None)
                            if ticket is not None:
                                job.upload_ticket = dict(ticket)
                        elapsed = now - job.last_time
                        if elapsed >= .2:
                            job.speed = max(0, done - job.last_done) / elapsed
                            job.last_time, job.last_done = now, done
                        if now - job.last_emit >= .1 or done == total:
                            job.last_emit = now
                            self._emit(job)

                options = dict(progress=progress, pause_event=job.pause_event,
                               cancel_event=job.cancel_event)
                if job.cancel_event.is_set():
                    if job.direction == 'download' and job.started:
                        result = client.cancel_download(job.target)
                    elif job.direction == 'upload' and job.upload_ticket is not None:
                        result = client.cancel_upload(job.upload_ticket)
                    elif job.direction == 'upload' or not job.started:
                        # Client guarantees a ticket exists before BEGIN can
                        # be sent. No ticket means no remote upload to discard.
                        result = {'status': 'cancelled', 'bytes': 0, 'total': job.total}
                else:
                    client.connect()
                    job.started = True
                    if job.direction == 'upload':
                        upload_started = True
                        result = client.upload(job.source, remote_name=job.target, **options)
                    else:
                        result = client.download(job.source, job.target, **options)
                with self._lock:
                    state = result.get('status')
                    if state not in ('complete', 'paused', 'cancelled'):
                        raise RuntimeError('服务返回了未知任务状态')
                    job.state = state
                    job.done = result.get('bytes', job.done)
                    job.total = result.get('total', job.total)
                    if result.get('upload_ticket') is not None:
                        job.upload_ticket = dict(result['upload_ticket'])
                    if state in ('complete', 'cancelled'):
                        job.upload_ticket = None
                    if state == 'complete':
                        digest = result.get('sha256', '')
                        job.message = 'SHA-256：%s' % digest if digest else '传输完成'
                    elif state == 'paused':
                        job.message = '已保留进度；继续时核对文件并断点续传'
                    else:
                        job.message = '已取消，临时数据已清理'
                    job.speed = 0
                    job.active = False
                    # Cancel can arrive after the transport has decided to
                    # pause but before its response reaches this thread.
                    if state == 'paused' and job.cancel_event.is_set():
                        job.state = 'cancelling'
                        job.message = '正在清理临时数据'
                        job.queued = True
                        self._work.put(job.id)
                    self._emit(job)
                if state == 'complete':
                    self.refresh()
            except Exception as exc:
                with self._lock:
                    if job.direction == 'upload' and upload_started and client is not None:
                        ticket = getattr(client, 'upload_ticket', None)
                        if ticket is not None:
                            job.upload_ticket = dict(ticket)
                    job.active = False
                    job.state = 'paused' if self._stop.is_set() else 'error'
                    job.speed = 0
                    job.message = str(exc)
                    if job.cancel_event.is_set() and not self._stop.is_set():
                        job.message = '清理未完成：%s；请点击继续重试。' % exc
                    self._emit(job)
                if client is not None:
                    self._close_client(client)
                    client = None
            heartbeat_at = time.monotonic() + 15
        if client is not None:
            self._close_client(client)


STATE_LABELS = {
    'queued': '等待中', 'running': '传输中', 'pausing': '正在暂停',
    'paused': '已暂停', 'cancelling': '正在取消', 'cancelled': '已取消',
    'complete': '已完成', 'error': '出错，可重试',
}


class HarborWindow:
    def __init__(self, root, config_path=None, workers=4):
        global tk, filedialog, messagebox, ttk
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        self.root = root
        self.worker_count = workers
        self.pool: Optional[TransferPool] = None
        self._closing = False
        self._connected = False
        self._can_upload = False
        self._can_download = False
        self._job_data = {}
        self._remote_files = {}
        self._local_files = {}
        root.title('Harbor · 安全文件传输')
        root.geometry('1160x830')
        root.minsize(920, 660)
        root.protocol('WM_DELETE_WINDOW', self._on_close)
        self.config_path = tk.StringVar(value=str(config_path or ''))
        self.local_folder = tk.StringVar(value=str(Path.home() / 'Downloads'))
        if not Path(self.local_folder.get()).is_dir():
            self.local_folder.set(str(Path.home()))
        self.connection_text = tk.StringVar(value='未连接 · 双向 TLS 证书认证')
        self.identity_text = tk.StringVar(value='选择客户端 JSON 配置以开始')
        self.summary_text = tk.StringVar(value='就绪')
        self.detail_text = tk.StringVar(value='暂停保留进度；取消会清理服务端上传事务或本地下载临时文件。')
        self._build()
        self._refresh_local()
        self._poll_id = root.after(80, self._poll)

    def _build(self):
        style = ttk.Style(self.root)
        style.configure('Title.TLabel', font=('Helvetica', 22, 'bold'))
        style.configure('Subtitle.TLabel', foreground='#5b6472')
        style.configure('Treeview', rowheight=27)
        style.configure('Treeview.Heading', font=('Helvetica', 11, 'bold'))
        style.configure('Accent.TButton', padding=(12, 7))
        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill='both', expand=True)
        header = ttk.Frame(outer)
        header.pack(fill='x')
        ttk.Label(header, text='Harbor', style='Title.TLabel').pack(side='left')
        ttk.Label(header, text='安全文件传输', style='Subtitle.TLabel', padding=(12, 0)).pack(side='left')
        ttk.Label(header, textvariable=self.connection_text).pack(side='right')
        connection = ttk.LabelFrame(outer, text='连接与身份', padding=10)
        connection.pack(fill='x', pady=(14, 10))
        connection.columnconfigure(1, weight=1)
        ttk.Label(connection, text='客户端配置').grid(row=0, column=0, padx=(0, 8))
        self.config_entry = ttk.Entry(connection, textvariable=self.config_path)
        self.config_entry.grid(row=0, column=1, sticky='ew')
        self.config_button = ttk.Button(connection, text='选择…', command=self._choose_config)
        self.config_button.grid(row=0, column=2, padx=8)
        self.connect_button = ttk.Button(connection, text='连接', style='Accent.TButton', command=self._connect)
        self.connect_button.grid(row=0, column=3)
        ttk.Label(connection, textvariable=self.identity_text, style='Subtitle.TLabel').grid(
            row=1, column=0, columnspan=4, sticky='w', pady=(9, 0))
        panes = ttk.Panedwindow(outer, orient='horizontal')
        panes.pack(fill='both', expand=True)
        local = ttk.LabelFrame(panes, text='本地文件', padding=10)
        remote = ttk.LabelFrame(panes, text='远端文件 · 当前账号独立空间', padding=10)
        panes.add(local, weight=1)
        panes.add(remote, weight=1)
        folder_row = ttk.Frame(local)
        folder_row.pack(fill='x', pady=(0, 8))
        ttk.Entry(folder_row, textvariable=self.local_folder).pack(side='left', fill='x', expand=True)
        ttk.Button(folder_row, text='文件夹…', command=self._choose_folder).pack(side='left', padx=(6, 0))
        ttk.Button(folder_row, text='刷新', command=self._refresh_local).pack(side='left', padx=(6, 0))
        remote_row = ttk.Frame(remote)
        remote_row.pack(fill='x', pady=(0, 8))
        ttk.Label(remote_row, text='多选文件可并行传输', style='Subtitle.TLabel').pack(side='left')
        self.refresh_button = ttk.Button(remote_row, text='刷新远端', command=self._refresh_remote, state='disabled')
        self.refresh_button.pack(side='right')
        self.local_tree = self._file_tree(local)
        self.remote_tree = self._file_tree(remote)
        local_actions = ttk.Frame(local)
        local_actions.pack(fill='x', pady=(8, 0))
        self.upload_selected = ttk.Button(local_actions, text='上传所选 ↑', command=self._upload_selected, state='disabled')
        self.upload_selected.pack(side='left')
        self.upload_files = ttk.Button(local_actions, text='选择文件上传…', command=self._choose_upload, state='disabled')
        self.upload_files.pack(side='left', padx=(6, 0))
        self.download_button = ttk.Button(remote, text='↓ 下载所选到本地文件夹', command=self._download_selected, state='disabled')
        self.download_button.pack(anchor='w', pady=(8, 0))
        tasks = ttk.LabelFrame(outer, text='传输任务 · %d 个并行工作连接' % self.worker_count, padding=10)
        tasks.pack(fill='both', expand=True, pady=(12, 0))
        task_toolbar = ttk.Frame(tasks)
        task_toolbar.pack(fill='x', pady=(0, 8))
        ttk.Label(task_toolbar, text='支持多选任务', style='Subtitle.TLabel').pack(side='left')
        for label, action in (('暂停', 'pause'), ('继续 / 重试', 'resume'), ('取消并清理', 'cancel')):
            ttk.Button(task_toolbar, text=label, command=lambda a=action: self._task_action(a)).pack(side='right', padx=(6, 0))
        self.tasks = self._tree(tasks, ('direction', 'name', 'progress', 'speed', 'state'),
                                ('方向', '文件', '进度', '速率', '状态'),
                                (65, 280, 240, 100, 125), height=6)
        self.tasks.bind('<<TreeviewSelect>>', self._show_detail)
        self.tasks.tag_configure('error', foreground='#b3342a')
        self.tasks.tag_configure('complete', foreground='#26704d')
        self.tasks.tag_configure('paused', foreground='#82621d')
        self.selected_progress = ttk.Progressbar(tasks, mode='determinate', maximum=100)
        self.selected_progress.pack(fill='x', pady=(8, 5))
        ttk.Label(tasks, textvariable=self.detail_text, wraplength=1040).pack(anchor='w', fill='x')
        ttk.Label(outer, textvariable=self.summary_text, style='Subtitle.TLabel').pack(fill='x', pady=(10, 0))
        self.local_tree.bind('<Double-1>', lambda event: self._upload_selected())
        self.remote_tree.bind('<Double-1>', lambda event: self._download_selected())

    def _tree(self, parent, columns, headings, widths, height=9):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='extended', height=height)
        scroll = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        for key, heading, width in zip(columns, headings, widths):
            tree.heading(key, text=heading)
            tree.column(key, width=width, minwidth=55, stretch=key in ('name', 'progress'))
        return tree

    def _file_tree(self, parent):
        return self._tree(parent, ('name', 'size', 'mtime'), ('文件名', '大小', '修改时间'), (230, 85, 140))

    def _choose_config(self):
        chosen = filedialog.askopenfilename(parent=self.root, title='选择客户端配置',
                                           filetypes=[('JSON 配置', '*.json'), ('全部文件', '*')])
        if chosen:
            self.config_path.set(chosen)

    def _connect(self):
        path = self.config_path.get().strip()
        if not path or not Path(path).is_file():
            messagebox.showerror('配置文件无效', '请选择存在的客户端 JSON 配置文件。', parent=self.root)
            return
        self.connect_button.configure(state='disabled')
        self.connection_text.set('正在连接 · 验证服务端与客户端证书…')
        if self.pool is None:
            self.config_path.set(str(Path(path).resolve()))
            self.config_entry.configure(state='disabled')
            self.config_button.configure(state='disabled')
            self.pool = TransferPool(self.config_path.get(), self.worker_count)
            self.pool.start()
        else:
            self.pool.reconnect()

    def _choose_folder(self):
        folder = filedialog.askdirectory(parent=self.root, title='选择本地文件夹',
                                         initialdir=self.local_folder.get(), mustexist=True)
        if folder:
            self.local_folder.set(folder)
            self._refresh_local()

    @staticmethod
    def _mtime(value):
        try:
            return time.strftime('%Y-%m-%d %H:%M', time.localtime(value))
        except (ValueError, OverflowError, TypeError):
            return '—'

    def _refresh_local(self):
        try:
            folder = Path(self.local_folder.get()).expanduser().resolve()
            if not folder.is_dir():
                raise ValueError('本地路径不是文件夹')
            rows = []
            for path in sorted(folder.iterdir(), key=lambda p: p.name.casefold()):
                if path.is_file() and not path.is_symlink():
                    stat = path.stat()
                    rows.append((path, stat.st_size, stat.st_mtime))
            self.local_folder.set(str(folder))
            self.local_tree.delete(*self.local_tree.get_children())
            self._local_files.clear()
            for index, (path, size, mtime) in enumerate(rows):
                item = 'local-%d' % index
                self._local_files[item] = path
                self.local_tree.insert('', 'end', iid=item, values=(path.name, format_bytes(size), self._mtime(mtime)))
        except (OSError, ValueError) as exc:
            self.summary_text.set('读取本地文件夹失败：%s' % exc)

    def _refresh_remote(self):
        if self.pool and self._can_download:
            self.summary_text.set('正在刷新远端文件…')
            self.pool.refresh()

    def _choose_upload(self):
        if not self._connected or not self._can_upload:
            return
        paths = filedialog.askopenfilenames(parent=self.root, title='选择上传文件（可多选）',
                                            initialdir=self.local_folder.get())
        self._queue_uploads(paths)

    def _upload_selected(self):
        if self._connected and self._can_upload:
            self._queue_uploads([self._local_files[item] for item in self.local_tree.selection()])

    def _queue_uploads(self, paths):
        errors = []
        for value in paths:
            path = Path(value)
            try:
                if not path.is_file() or path.is_symlink():
                    raise ValueError('请选择普通文件，不能上传符号链接')
                self.pool.submit('upload', str(path.resolve()), path.name, path.stat().st_size)
            except (OSError, ValueError) as exc:
                errors.append('%s：%s' % (path.name, exc))
        if errors:
            messagebox.showerror('部分文件未加入队列', '\n'.join(errors), parent=self.root)

    def _download_selected(self):
        if not self._connected or not self._can_download:
            return
        names = [self._remote_files[item]['name'] for item in self.remote_tree.selection()]
        if not names:
            return
        if any(name in ('', '.', '..') or '/' in name or '\\' in name
               or any(ord(char) < 32 or ord(char) == 127 for char in name)
               for name in names):
            messagebox.showerror('远端文件名无效', '所选文件名包含不安全的路径或控制字符。', parent=self.root)
            return
        folder = Path(self.local_folder.get()).expanduser()
        if not folder.is_dir():
            messagebox.showerror('下载目录无效', '请先选择存在的本地文件夹。', parent=self.root)
            return
        errors = []
        for name in names:
            try:
                item = next(row for row in self._remote_files.values() if row['name'] == name)
                target = folder.resolve() / name
                if target.is_symlink():
                    raise ValueError('下载目标不能是符号链接')
                if target.exists():
                    raise ValueError('本地同名文件或目录已存在；请选择其他下载文件夹，或先移走/删除现有目标后重试')
                self.pool.submit('download', name, str(target), item['size'])
            except (OSError, ValueError) as exc:
                errors.append('%s：%s' % (name, exc))
        if errors:
            messagebox.showerror('部分文件未加入队列', '\n'.join(errors), parent=self.root)

    def _task_action(self, action):
        if self.pool is None:
            return
        for job_id in self.tasks.selection():
            getattr(self.pool, action)(job_id)

    def _update_job(self, data):
        previous = self._job_data.get(data['id'], {})
        self._job_data[data['id']] = data
        name = Path(data['source']).name if data['direction'] == 'upload' else data['source']
        total, done = data['total'], data['done']
        percent = min(100, done * 100 / total) if total else (100 if data['state'] == 'complete' else 0)
        progress = '%.0f%% · %s / %s' % (percent, format_bytes(done), format_bytes(total))
        values = ('↑ 上传' if data['direction'] == 'upload' else '↓ 下载', name, progress,
                  format_bytes(data['speed']) + '/s' if data['speed'] else '—', STATE_LABELS.get(data['state'], data['state']))
        if self.tasks.exists(data['id']):
            self.tasks.item(data['id'], values=values, tags=(data['state'],))
        else:
            self.tasks.insert('', 'end', iid=data['id'], values=values, tags=(data['state'],))
        if data['state'] == 'error' and previous.get('state') != 'error':
            self.summary_text.set('%s：%s' % (name, data['message']))
            self.tasks.selection_set(data['id'])
            self.tasks.see(data['id'])
        if data['state'] == 'complete' and previous.get('state') != 'complete':
            self._refresh_local()
        self._show_detail()

    def _show_detail(self, event=None):
        selected = self.tasks.selection()
        if not selected:
            return
        data = self._job_data.get(selected[0])
        if data is None:
            return
        percent = min(100, data['done'] * 100 / data['total']) if data['total'] else (100 if data['state'] == 'complete' else 0)
        self.selected_progress['value'] = percent
        self.detail_text.set('%s → %s\n%s' % (data['source'], data['target'], data['message'] or STATE_LABELS[data['state']]))

    def _poll(self):
        if self._closing:
            return
        if self.pool is not None:
            # Bound each drain to preserve responsiveness under fast transfers.
            for _ in range(250):
                try:
                    kind, data = self.pool.events.get_nowait()
                except queue.Empty:
                    break
                if kind == 'connected':
                    self._connected = True
                    self._can_upload = data.get('can_upload', True)
                    self._can_download = data.get('can_download', True)
                    self.connection_text.set('已连接 · %s' % data.get('tls_version', 'TLS'))
                    rate = data.get('rate_bps', 0)
                    self.identity_text.set('身份：%s   |   等级：%s   |   账号共享带宽：%s   |   控制连接：%s' % (
                        data.get('username', '—'), data.get('tier', '—'),
                        format_bytes(rate) + '/s' if rate else '不限速', data.get('connection_id', '—')))
                    self.connect_button.configure(text='重新连接', state='normal')
                    for button in (self.upload_selected, self.upload_files):
                        button.configure(state='normal' if self._can_upload else 'disabled')
                    for button in (self.refresh_button, self.download_button):
                        button.configure(state='normal' if self._can_download else 'disabled')
                    self.summary_text.set('证书认证通过；%d 个工作连接持续复用。' % self.worker_count)
                elif kind == 'connection_error':
                    self._connected = False
                    self.connection_text.set('控制连接断开 · 可重新连接')
                    self.connect_button.configure(text='重新连接', state='normal')
                    for button in (self.refresh_button, self.upload_selected, self.upload_files, self.download_button):
                        button.configure(state='disabled')
                    self.summary_text.set('连接失败：%s' % data)
                    if not self._job_data:
                        # A mistaken configuration must be correctable without
                        # restarting the app. No jobs exist to migrate here.
                        self.pool.close()
                        self.pool = None
                        self.config_entry.configure(state='normal')
                        self.config_button.configure(state='normal')
                    messagebox.showerror('连接或证书验证失败', data, parent=self.root)
                    if self.pool is None:
                        break
                elif kind == 'files':
                    self.remote_tree.delete(*self.remote_tree.get_children())
                    self._remote_files.clear()
                    for index, item in enumerate(data):
                        key = 'remote-%d' % index
                        self._remote_files[key] = item
                        self.remote_tree.insert('', 'end', iid=key, values=(item['name'], format_bytes(item['size']), self._mtime(item['mtime'])))
                    self.summary_text.set('远端共有 %d 个文件；暂停任务保留进度，继续时自动校验。' % len(data))
                elif kind == 'job':
                    self._update_job(data)
                elif kind in ('log', 'list_error'):
                    self.summary_text.set(data)
        self._poll_id = self.root.after(80, self._poll)

    def _on_close(self):
        if self._closing:
            return
        self._closing = True
        if self.pool is not None:
            self.pool.close()
        self.root.after_cancel(self._poll_id)
        self.root.destroy()


def main(config_path=None, workers=4):
    import tkinter as tk

    root = tk.Tk()
    HarborWindow(root, config_path=config_path, workers=workers)
    root.mainloop()
