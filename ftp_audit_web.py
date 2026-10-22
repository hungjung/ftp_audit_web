#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP 安全稽核 Web 工具 (ftp_audit_web.py)
---------------------------------------------------------------
功能:
  1. 網頁上傳「IP 清單 (TXT)」與「字典檔 (TXT)」
  2. 檢測 FTP 匿名登入 / 弱密碼
  3. 登入成功後遞迴掃描目錄,找出 PDF 與圖片檔並統計數量
  4. 可在網頁上直接「預覽」與「下載」掃到的檔案

用途:僅限對「自己機關擁有或已取得書面授權」的主機進行資安稽核。
     未經授權對他人系統進行密碼嘗試在多數司法管轄區屬違法行為。

本機自帶 Bootstrap(離線內網可用,不依賴外網 CDN)。
資料夾結構必須維持如下,static/ 要與本程式放在同一層:
  ftp_audit/
  ├─ ftp_audit_web.py
  └─ static/
     ├─ bootstrap.min.css
     ├─ bootstrap.bundle.min.js
     ├─ bootstrap-icons.css
     └─ fonts/
        ├─ bootstrap-icons.woff2
        └─ bootstrap-icons.woff

部署 (Kali Linux):
  pip install flask          # 或  pip install -r requirements.txt
  python3 ftp_audit_web.py                 # 預設只綁 127.0.0.1:8000
  python3 ftp_audit_web.py --host 0.0.0.0 --port 8000   # 對外提供(請自行評估風險)

字典檔格式(擇一,程式自動判斷):
  (A) 每行 user:password        例如  admin:admin123
  (B) 每行只有密碼              程式會自動配對常見帳號 (admin/root/ftp/...)
"""

import argparse
import ftplib
import io
import os
import re
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

_MONTHS = {'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
           'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'}

from flask import Flask, request, jsonify, Response, abort

# ------------------------- 設定參數 -------------------------
MAX_DEPTH = 3                       # 目錄遞迴最大深度
MAX_FILES_PER_HOST = 1000           # 每台主機最多收集的檔案數
PREVIEW_MAX_BYTES = 30 * 1024 * 1024  # 預覽/下載單檔上限 30MB

IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.svg'}
PDF_EXTS = {'.pdf'}

CONTENT_TYPES = {
    '.pdf': 'application/pdf',
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png', '.gif': 'image/gif', '.bmp': 'image/bmp',
    '.webp': 'image/webp', '.tif': 'image/tiff', '.tiff': 'image/tiff',
    '.svg': 'image/svg+xml',
}

COMMON_USERS = ['admin', 'root', 'ftp', 'ftpuser', 'user', 'test', 'guest']

DEFAULT_CREDS = [
    ('admin', 'admin'), ('admin', '123456'), ('admin', 'password'),
    ('admin', 'admin123'), ('root', 'root'), ('root', '123456'),
    ('root', 'toor'), ('ftp', 'ftp'), ('ftpuser', 'ftpuser'),
    ('test', 'test'), ('user', 'user'), ('guest', 'guest'),
]

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# static_folder 綁定腳本所在目錄,離線自帶 Bootstrap,不依賴外網
app = Flask(__name__, static_folder=os.path.join(_BASE_DIR, 'static'), static_url_path='/static')
JOBS = {}  # job_id -> {status, total, done, results, truncated_creds}


# ------------------------- 共用工具 -------------------------
def _close(ftp):
    try:
        ftp.quit()
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass


class _RobustFTP(ftplib.FTP):
    """可選擇性把被動模式的資料連線導向『控制連線的 IP』。
    對多網卡 / NAT 下 PASV 回報錯誤位址而造成 426 的伺服器特別有效。"""
    _use_control_host = False

    def makepasv(self):
        host, port = super().makepasv()
        if self._use_control_host:
            try:
                host = self.sock.getpeername()[0]  # 改用控制連線對端(必然可達)
            except Exception:
                pass
        return host, port


# 資料連線模式(由可靠到保底):被動 → 被動+控制IP覆寫 → 主動
DATA_MODES = [
    {'label': 'PASV',          'passive': True,  'ctrl_host': False},
    {'label': 'PASV+控制IP',    'passive': True,  'ctrl_host': True},
    {'label': 'PORT(主動)',    'passive': False, 'ctrl_host': False},
]


def ftp_connect(host, port, user, password, timeout):
    """建立並登入 FTP 連線(encoding 用 latin-1 避免檔名解碼錯誤)。"""
    ftp = _RobustFTP()
    ftp.encoding = 'latin-1'
    ftp.connect(host, port, timeout=timeout)
    ftp.login(user, password)
    return ftp


def _apply_mode(ftp, mode):
    ftp._use_control_host = mode.get('ctrl_host', False)
    ftp.set_pasv(mode.get('passive', True))


def _open_apply(host, port, user, password, mode, timeout):
    """建立連線、套用資料連線模式、設二進位。
    注意:不可在列目錄前額外開啟任何資料連線(如預敲、先試 MLSD)——
    有些伺服器『LIST 之前只要開過一次資料連線,下一次 LIST 就會 426』。"""
    ftp = ftp_connect(host, port, user, password, timeout)
    _apply_mode(ftp, mode)
    try:
        ftp.voidcmd('TYPE I')  # 僅送控制指令,不開資料連線;retrlines 會自行改回 TYPE A
    except Exception:
        pass
    return ftp


def try_login(host, port, user, password, timeout):
    """嘗試一組帳密,成功回傳 True。"""
    try:
        ftp = ftp_connect(host, port, user, password, timeout)
    except ftplib.all_errors:
        return False
    try:
        try:
            ftp.nlst()
        except Exception:
            pass  # 登入已成功;列目錄失敗(權限/編碼)不影響判定
        return True
    finally:
        _close(ftp)


def parse_lines(data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        text = data.decode('latin-1', 'ignore')
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith('#')]


def parse_target(line):
    """解析一行 IP,回傳 (host, port 或 None)。"""
    if line.count(':') == 1:
        h, p = line.split(':', 1)
        try:
            return (h.strip(), int(p))
        except ValueError:
            return (h.strip(), None)
    return (line, None)


def parse_creds(data, max_creds):
    """解析字典檔。自動判斷 user:pass 或純密碼清單。回傳 (combos, truncated)。"""
    lines = parse_lines(data)
    combos = []
    if any(':' in ln for ln in lines):
        for ln in lines:
            if ':' in ln:
                u, p = ln.split(':', 1)
                combos.append((u, p))
    else:
        for pw in lines:
            for u in COMMON_USERS:
                combos.append((u, pw))
    truncated = len(combos) > max_creds
    return combos[:max_creds], truncated


# ------------------------- 目錄掃描 -------------------------
def _join(path, name):
    if not path or path == '/':
        return '/' + name
    return path.rstrip('/') + '/' + name


def _display_name(name):
    """連線用 latin-1 解碼;還原檔名真正的編碼供顯示(先試 UTF-8,再試 Big5/CP950)。
    FTP 指令仍用原始 latin-1 字串,確保下載路徑位元組正確。"""
    try:
        raw = name.encode('latin-1')
    except Exception:
        return name
    for enc in ('utf-8', 'cp950', 'big5'):
        try:
            dec = raw.decode(enc)
        except Exception:
            continue
        if any(ord(c) > 127 for c in dec):  # 解出中文才採用;純 ASCII 保留原樣
            return dec
    return name


def _parse_list_line(line):
    """解析 LIST 回傳的一行,回傳 (name, is_dir, size) 或 None。
    支援 Unix (ls -l,含欄位數不同的變體) 與 MS-DOS/IIS 兩種格式。"""
    line = line.rstrip('\r\n')
    if not line.strip():
        return None
    tokens = line.split()
    if not tokens:
        return None

    # MS-DOS / IIS 格式:  07-17-26  12:53PM  <DIR>  name   或   ... 318976 name
    if re.match(r'^\d\d-\d\d-\d{2,4}$', tokens[0]) and len(tokens) >= 4:
        token = tokens[2]
        rest = line.split(None, 3)
        name = rest[3] if len(rest) > 3 else None
        if not name or name in ('.', '..'):
            return None
        if token.upper() == '<DIR>':
            return (name, True, None)
        try:
            return (name, False, int(token))
        except ValueError:
            return (name, False, None)

    # Unix 格式:  -rwx------ 1 user group 318976 Jul 17 2026 name
    # (有些伺服器缺群組欄或欄數不同,故以「月份欄」來定位檔名,不假設固定欄數)
    first = line[0]
    if first in 'd-lcbps':
        is_dir = (first == 'd')
        is_link = (first == 'l')
        name, size = None, None
        for i in range(1, len(tokens) - 1):
            if tokens[i] in _MONTHS and i + 2 < len(tokens):
                try:
                    size = int(tokens[i - 1])  # 月份前一欄為大小
                except (ValueError, IndexError):
                    size = None
                parts = line.split(None, i + 3)  # 月、日、時間/年 之後即檔名
                name = parts[i + 3] if len(parts) > i + 3 else None
                break
        if name is None:  # 找不到月份欄時,退回標準 9 欄假設
            parts = line.split(None, 8)
            if len(parts) >= 9:
                name = parts[8]
                try:
                    size = int(parts[4])
                except (ValueError, IndexError):
                    size = None
        if not name or name in ('.', '..'):
            return None
        if is_link:
            name = name.split(' -> ')[0]  # 符號連結取箭頭前的名稱
            is_dir = False                # 連結一律當檔案,避免誤遞迴
            size = None
        return (name, is_dir, size)

    return None


def _list_dir(ftp, path):
    """回傳 [(name, is_dir, size)]。
    先 CWD 切進目標目錄,再用『不帶參數』的指令列出 —— 有些伺服器不接受
    LIST/MLSD/NLST 帶路徑(會回 426 或錯誤),只接受列出當前目錄。
    三層:MLSD → LIST → NLST+SIZE。
    注意:資料傳輸類錯誤(如 426)會『往外拋出』,交給呼叫端重連重試;
          只有『目錄確實是空的』才回 []。"""
    ftp.cwd(path or '/')  # 切不進去 → 拋出,呼叫端處理

    # 1) LIST(不帶參數)—— 優先,且只開『一次』資料連線。
    #    不先試 MLSD:ftplib 的 MLSD 會先開資料連線才收到 502,
    #    這會干擾『固定被動埠』伺服器,害接下來的 LIST 426。
    #    資料傳輸錯誤(426 等)會往外拋,交呼叫端重連重試;
    #    只有 LIST 指令本身不被支援(error_perm)才退回 MLSD。
    try:
        lines = []
        ftp.retrlines('LIST', lines.append)
        parsed = [r for r in (_parse_list_line(ln) for ln in lines) if r]
        if parsed or not lines:
            return parsed  # 有解析到內容,或確實是空目錄
        # LIST 有回內容但一行都解析不出 → 落到 MLSD 嘗試補救
    except ftplib.error_perm:
        pass  # LIST 不被支援(極罕見)→ 試 MLSD

    # 2) MLSD(不帶參數)
    try:
        out = []
        for name, facts in ftp.mlsd():
            if name in ('.', '..'):
                continue
            typ = facts.get('type', '')
            if typ == 'dir':
                out.append((name, True, None))
            elif typ == 'file':
                sz = facts.get('size')
                out.append((name, False, int(sz) if sz and sz.isdigit() else None))
        return out
    except ftplib.error_perm:
        pass  # MLSD 不支援 → 試 NLST

    # 3) NLST(不帶參數)+ SIZE
    out = []
    names = ftp.nlst()
    for n in names:
        base = n.rsplit('/', 1)[-1]
        if base in ('.', '..'):
            continue
        sz, is_dir = None, False
        try:
            ftp.voidcmd('TYPE I')
            sz = ftp.size(base)
            is_dir = (sz is None)
        except Exception:
            ext = os.path.splitext(base)[1].lower()
            is_dir = ext not in IMAGE_EXTS and ext not in PDF_EXTS
        out.append((base, is_dir, sz))
    return out


def _walk_fresh(host, port, user, password, mode, start, timeout,
                max_depth=MAX_DEPTH, max_files=MAX_FILES_PER_HOST, tries=4):
    """遞迴掃描:每個目錄都用『全新連線』列出,並在失敗時重試重連。
    專治『固定單一被動埠、連續連線易 426』的伺服器——單一目錄失敗不會
    拖垮整體;某目錄多次重試仍失敗就略過該目錄。"""
    found = []
    visited = set()
    stack = [(start, 0)]
    while stack and len(found) < max_files:
        path, depth = stack.pop()
        key = path or '/'
        if key in visited or depth > max_depth:
            continue
        visited.add(key)

        entries = None
        for attempt in range(tries):
            ftp = None
            try:
                ftp = _open_apply(host, port, user, password, mode, timeout)
                entries = _list_dir(ftp, path)
                break  # 成功
            except Exception:
                entries = None  # 多為 426,重連再試
            finally:
                if ftp is not None:
                    _close(ftp)
            if attempt + 1 < tries:
                time.sleep(0.4)
        if entries is None:
            continue  # 此目錄實在列不出 → 略過,不中斷整體

        for name, is_dir, size in entries:
            if is_dir:
                stack.append((_join(path, name), depth + 1))
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in IMAGE_EXTS:
                kind = 'image'
            elif ext in PDF_EXTS:
                kind = 'pdf'
            else:
                continue
            found.append({'path': _join(path, name),
                          'name': _display_name(name),
                          'ext': ext, 'kind': kind, 'size': size})
            if len(found) >= max_files:
                break
    return found


def scan_with_fallback(host, port, user, password, timeout):
    """掃描檔案,依序嘗試多種資料連線模式,選第一個可用者。
    回傳 (files, mode)。全部失敗則拋出例外(避免默默回 0)。
    對每個模式先『用全新連線 + 重試』驗證能列出起始目錄,再以
    _walk_fresh(每目錄全新連線)完成整個掃描,耐受固定被動埠的 flaky 行為。"""
    last_err = None
    for mode in DATA_MODES:
        # 被動模式多試幾次:固定被動埠常「第一次 426、重連才通」。主動模式只試 1 次。
        tries = 4 if mode['passive'] else 1
        start, ok = '/', False
        for attempt in range(tries):
            ftp = None
            try:
                ftp = _open_apply(host, port, user, password, mode, timeout)
                start = ftp.pwd() or '/'
                _list_dir(ftp, start)  # 能列出起始目錄才算此模式可用(拋出即失敗)
                ok = True
            except Exception as e:
                last_err = '%s(第%d次): %s' % (mode['label'], attempt + 1, e)
            finally:
                if ftp is not None:
                    _close(ftp)
            if ok:
                break
            if attempt + 1 < tries:
                time.sleep(0.4)
        if not ok:
            continue
        # 此模式可用 → 用每目錄全新連線的 walk 完成掃描
        files = _walk_fresh(host, port, user, password, mode, start, timeout)
        return files, mode
    raise IOError('資料連線在所有模式皆失敗 (最後錯誤 %s)' % last_err)


def walk_ftp(ftp, start=None, max_depth=MAX_DEPTH, max_files=MAX_FILES_PER_HOST):
    """遞迴掃描,收集 PDF 與圖片檔。"""
    try:
        ftp.voidcmd('TYPE I')  # 二進位模式,SIZE 才可用
    except Exception:
        pass
    if start is None:
        # 從登入後的目錄起掃(非 chroot 的伺服器,家目錄未必是 '/')
        try:
            start = ftp.pwd() or '/'
        except Exception:
            start = '/'
    found = []
    visited = set()
    stack = [(start, 0)]
    while stack and len(found) < max_files:
        path, depth = stack.pop()
        key = path or '/'
        if key in visited or depth > max_depth:
            continue
        visited.add(key)
        try:
            entries = _list_dir(ftp, path)
        except Exception:
            entries = []  # 此連線列不出(如 426);單連線版不重連,略過
        for name, is_dir, size in entries:
            if is_dir:
                stack.append((_join(path, name), depth + 1))
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in IMAGE_EXTS:
                kind = 'image'
            elif ext in PDF_EXTS:
                kind = 'pdf'
            else:
                continue
            found.append({'path': _join(path, name),      # 原始位元組路徑,供 FTP RETR
                          'name': _display_name(name),     # 還原後的可讀檔名,供 UI 顯示
                          'ext': ext, 'kind': kind, 'size': size})
            if len(found) >= max_files:
                break
    return found


# ------------------------- 主機稽核 -------------------------
def audit_host(host, port, creds, timeout):
    res = {'host': host, 'port': port, 'reachable': False, 'anonymous': False,
           'weak_creds': [], 'login_user': None, 'login_pass': None, 'dmode': None,
           'pdf_count': 0, 'image_count': 0, 'files': [], 'error': ''}

    # 連線測試
    try:
        with socket.create_connection((host, port), timeout=timeout):
            res['reachable'] = True
    except OSError as e:
        res['error'] = str(e)
        return res

    # 匿名登入
    anon = None
    for u, p in (('anonymous', 'anonymous@example.com'), ('ftp', 'ftp@example.com')):
        if try_login(host, port, u, p, timeout):
            res['anonymous'] = True
            anon = (u, p)
            break

    # 弱密碼
    for u, p in creds:
        if try_login(host, port, u, p, timeout):
            res['weak_creds'].append('%s:%s' % (u, p))

    # 選一組可用帳密來掃目錄(優先匿名)
    working = anon
    if not working and res['weak_creds']:
        u, p = res['weak_creds'][0].split(':', 1)
        working = (u, p)

    if working:
        res['login_user'], res['login_pass'] = working
        try:
            files, mode = scan_with_fallback(host, port, working[0], working[1], timeout)
            res['dmode'] = mode
            for f in files:
                f['id'] = uuid.uuid4().hex
            res['files'] = files
            res['pdf_count'] = sum(1 for f in files if f['kind'] == 'pdf')
            res['image_count'] = sum(1 for f in files if f['kind'] == 'image')
        except Exception as e:
            res['error'] = 'walk failed: %s' % e
    return res


def run_scan(job_id, targets, creds, timeout, threads):
    job = JOBS[job_id]
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(audit_host, h, p, creds, timeout): (h, p) for h, p in targets}
        for fut in as_completed(futs):
            h, p = futs[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {'host': h, 'port': p, 'reachable': False, 'anonymous': False,
                     'weak_creds': [], 'files': [], 'pdf_count': 0, 'image_count': 0,
                     'error': str(e)}
            results.append(r)
            job['done'] += 1
    job['results'] = results
    job['status'] = 'done'


def _find_file(job, file_id):
    for r in job['results']:
        for f in r.get('files', []):
            if f.get('id') == file_id:
                return r, f
    return None, None


def download_ftp_file(host, port, user, password, path, timeout, max_bytes, dmode=None):
    """下載單一檔案;先試掃描時記錄到的資料連線模式,失敗再試其餘模式。"""
    # 先試掃描成功時用的模式,再補上其餘模式(去重)
    modes = []
    if dmode:
        modes.append(dmode)
    for m in DATA_MODES:
        if m not in modes:
            modes.append(m)

    # 拆成目錄 + 檔名:先 CWD 再 RETR 檔名(與列目錄一致,相容不接受帶路徑的伺服器)
    d, base = path.rsplit('/', 1)
    d = d or '/'

    last_err = None
    # 每種模式各重試幾次(被動模式需預敲防火牆通道,偶爾仍需重連)
    attempts = [(mode, t) for mode in modes
                for t in range(4 if mode.get('passive') else 1)]
    for mode, _t in attempts:
        ftp = _open_apply(host, port, user, password, mode, timeout)  # 含被動預敲
        buf = io.BytesIO()
        state = {'n': 0}

        def cb(data):
            state['n'] += len(data)
            if state['n'] > max_bytes:
                raise IOError('file exceeds preview limit')
            buf.write(data)

        try:
            try:
                ftp.cwd(d)
            except Exception:
                pass
            ftp.retrbinary('RETR ' + base, cb)
            return buf.getvalue()
        except IOError as e:
            if 'exceeds preview limit' in str(e):
                _close(ftp)
                raise  # 超過大小上限不是模式問題,直接往外拋
            last_err = e
        except Exception as e:
            last_err = e
        finally:
            _close(ftp)
    raise IOError('下載失敗 (所有資料連線模式皆不可用): %s' % last_err)


# ------------------------- Flask 路由 -------------------------
@app.route('/')
def index():
    return Response(PAGE, mimetype='text/html')


@app.route('/scan', methods=['POST'])
def scan():
    ip_file = request.files.get('ips')
    if not ip_file or not ip_file.filename:
        return jsonify({'error': '請上傳 IP 清單檔'}), 400

    default_port = int(request.form.get('port', 21))
    timeout = max(1, int(request.form.get('timeout', 5)))
    threads = max(1, int(request.form.get('threads', 20)))
    max_creds = max(1, int(request.form.get('max_creds', 500)))

    raw = parse_lines(ip_file.read())
    targets = []
    for ln in raw:
        t = parse_target(ln)
        if t:
            h, p = t
            targets.append((h, p if p else default_port))
    if not targets:
        return jsonify({'error': 'IP 清單為空或格式錯誤'}), 400

    dict_file = request.files.get('dict')
    truncated = False
    if dict_file and dict_file.filename:
        creds, truncated = parse_creds(dict_file.read(), max_creds)
    else:
        creds = DEFAULT_CREDS

    job_id = uuid.uuid4().hex
    JOBS[job_id] = {'status': 'running', 'total': len(targets), 'done': 0,
                    'results': [], 'cred_count': len(creds), 'truncated': truncated}
    threading.Thread(target=run_scan, args=(job_id, targets, creds, timeout, threads),
                     daemon=True).start()
    return jsonify({'job_id': job_id, 'total': len(targets),
                    'cred_count': len(creds), 'truncated': truncated})


@app.route('/status/<job_id>')
def status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404
    resp = {'status': job['status'], 'total': job['total'], 'done': job['done'],
            'cred_count': job.get('cred_count'), 'truncated': job.get('truncated')}
    if job['status'] == 'done':
        # 送給前端的結果不含密碼掃目錄用的 login_pass(弱密碼本身仍回報於 weak_creds)
        clean = []
        for r in job['results']:
            clean.append({
                'host': r['host'], 'port': r['port'], 'reachable': r['reachable'],
                'anonymous': r['anonymous'], 'weak_creds': r['weak_creds'],
                'pdf_count': r['pdf_count'], 'image_count': r['image_count'],
                'error': r['error'],
                'dmode': r['dmode']['label'] if r.get('dmode') else None,
                'files': [{'id': f['id'], 'name': f['name'], 'path': f['path'],
                           'kind': f['kind'], 'size': f['size']} for f in r.get('files', [])],
            })
        resp['results'] = clean
    return jsonify(resp)


def _serve_file(job_id, file_id, as_attachment):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    r, f = _find_file(job, file_id)
    if not r or not f:
        abort(404)
    try:
        data = download_ftp_file(r['host'], r['port'], r['login_user'], r['login_pass'],
                                 f['path'], timeout=15, max_bytes=PREVIEW_MAX_BYTES,
                                 dmode=r.get('dmode'))
    except Exception as e:
        return Response('取得檔案失敗: %s' % e, status=502, mimetype='text/plain')
    ct = CONTENT_TYPES.get(f['ext'], 'application/octet-stream')
    headers = {}
    if as_attachment:
        safe = f['name'].encode('ascii', 'ignore').decode() or ('file' + f['ext'])
        headers['Content-Disposition'] = 'attachment; filename="%s"' % safe
    return Response(data, mimetype=ct, headers=headers)


@app.route('/preview/<job_id>/<file_id>')
def preview(job_id, file_id):
    return _serve_file(job_id, file_id, as_attachment=False)


@app.route('/download/<job_id>/<file_id>')
def download(job_id, file_id):
    return _serve_file(job_id, file_id, as_attachment=True)


# ------------------------- 前端頁面 -------------------------
PAGE = """<!doctype html>
<html lang="zh-Hant" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FTP 資安稽核</title>
<link href="/static/bootstrap.min.css" rel="stylesheet">
<link href="/static/bootstrap-icons.css" rel="stylesheet">
<style>
  body{background:#0e131b}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  #mBody img{max-width:100%;max-height:78vh;display:block}
  #mBody iframe{width:100%;height:78vh;border:0;background:#fff}
  .file-chip .nm{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .host-vuln{border-left:4px solid var(--bs-danger)!important}
</style>
</head>
<body>
<nav class="navbar bg-body-tertiary border-bottom">
  <div class="container-fluid px-4">
    <span class="navbar-brand mb-0 h1"><i class="bi bi-shield-lock"></i> FTP 資安稽核工具</span>
    <span class="text-warning small"><i class="bi bi-exclamation-triangle"></i> 僅限對已獲授權之機關主機使用</span>
  </div>
</nav>

<div class="container py-4" style="max-width:1100px">

  <div class="card mb-4 shadow-sm">
    <div class="card-body">
      <form id="f">
        <div class="row g-3">
          <div class="col-12">
            <label class="form-label">IP 清單檔 (TXT,每行一個 IP,可用 ip:port) <span class="text-danger">*必填</span></label>
            <input class="form-control" type="file" name="ips" accept=".txt" required>
          </div>
          <div class="col-12">
            <label class="form-label">字典檔 (TXT,user:password 或純密碼清單;留空用內建字典)</label>
            <input class="form-control" type="file" name="dict" accept=".txt">
          </div>
          <div class="col-6 col-md-3"><label class="form-label">預設 Port</label>
            <input class="form-control" type="number" name="port" value="21" min="1" max="65535"></div>
          <div class="col-6 col-md-3"><label class="form-label">逾時 (秒)</label>
            <input class="form-control" type="number" name="timeout" value="5" min="1" max="60"></div>
          <div class="col-6 col-md-3"><label class="form-label">併發數</label>
            <input class="form-control" type="number" name="threads" value="20" min="1" max="200"></div>
          <div class="col-6 col-md-3"><label class="form-label">每台密碼上限</label>
            <input class="form-control" type="number" name="max_creds" value="500" min="1"></div>
        </div>
        <button id="go" class="btn btn-primary mt-3" type="submit">
          <i class="bi bi-search"></i> 開始掃描</button>
      </form>
      <div id="prog" class="mt-3 d-none">
        <div class="progress" role="progressbar" style="height:10px">
          <div id="barfill" class="progress-bar progress-bar-striped progress-bar-animated" style="width:0%"></div>
        </div>
        <div class="text-secondary small mt-2" id="progtxt"></div>
      </div>
    </div>
  </div>

  <div id="summary" class="mb-3"></div>
  <div id="results"></div>
</div>

<div class="modal fade" id="previewModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header py-2">
        <h6 class="modal-title mono text-truncate me-3" id="mName"></h6>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="關閉"></button>
      </div>
      <div class="modal-body p-0 d-flex align-items-center justify-content-center bg-dark"
           id="mBody" style="min-height:360px"></div>
    </div>
  </div>
</div>

<script src="/static/bootstrap.bundle.min.js"></script>
<script>
let jobId=null, poll=null, previewModal=null;
const $=s=>document.querySelector(s);
document.addEventListener("DOMContentLoaded",()=>{
  previewModal=new bootstrap.Modal("#previewModal");
  $("#previewModal").addEventListener("hidden.bs.modal",()=>{$("#mBody").innerHTML="";});
});

$("#f").addEventListener("submit", async e=>{
  e.preventDefault();
  $("#go").disabled=true; $("#results").innerHTML=""; $("#summary").innerHTML="";
  $("#prog").classList.remove("d-none"); $("#barfill").style.width="0%";
  $("#progtxt").textContent="建立掃描工作中…";
  const fd=new FormData($("#f"));
  let r;
  try{ r=await (await fetch("/scan",{method:"POST",body:fd})).json(); }
  catch(_){ $("#progtxt").textContent="無法連線到伺服器"; $("#go").disabled=false; return; }
  if(r.error){ $("#progtxt").textContent="錯誤:"+r.error; $("#go").disabled=false; return; }
  jobId=r.job_id;
  let note="共 "+r.total+" 個目標,字典 "+r.cred_count+" 組";
  if(r.truncated) note+="(已截斷至上限)";
  $("#progtxt").textContent=note+" — 掃描中…";
  poll=setInterval(checkStatus,1200);
});

async function checkStatus(){
  const s=await (await fetch("/status/"+jobId)).json();
  const pct=s.total? Math.round(s.done/s.total*100):0;
  $("#barfill").style.width=pct+"%";
  $("#progtxt").textContent="進度 "+s.done+" / "+s.total+" ("+pct+"%)";
  if(s.status==="done"){
    clearInterval(poll); $("#go").disabled=false;
    $("#barfill").classList.remove("progress-bar-animated");
    render(s.results);
  }
}

function fmtSize(n){ if(n==null) return ""; if(n<1024) return n+" B";
  if(n<1048576) return (n/1024).toFixed(1)+" KB"; return (n/1048576).toFixed(1)+" MB"; }
function esc(s){ return (s+"").replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function render(results){
  const vuln=results.filter(r=>r.anonymous||r.weak_creds.length);
  const okUp=results.filter(r=>r.reachable&&!r.anonymous&&!r.weak_creds.length);
  const down=results.filter(r=>!r.reachable);
  let pdf=0,img=0; vuln.forEach(r=>{pdf+=r.pdf_count;img+=r.image_count;});
  $("#summary").innerHTML=
    '<div class="alert alert-secondary mb-0 d-flex flex-wrap gap-3 align-items-center">'+
    '<span>掃描完成:共 <b>'+results.length+'</b> 台</span>'+
    '<span class="badge text-bg-danger">發現問題 '+vuln.length+' 台</span>'+
    '<span class="badge text-bg-success">無問題 '+okUp.length+' 台</span>'+
    '<span class="badge text-bg-secondary">無法連線 '+down.length+' 台</span>'+
    '<span class="ms-auto">合計 <i class="bi bi-file-earmark-pdf"></i> PDF <b>'+pdf+
    '</b> · <i class="bi bi-image"></i> 圖片 <b>'+img+'</b></span></div>';

  const box=$("#results"); box.innerHTML="";
  vuln.forEach(r=>box.appendChild(hostCard(r,true)));

  if(okUp.length||down.length){
    const btn=document.createElement("button");
    btn.className="btn btn-sm btn-outline-secondary mb-2";
    btn.setAttribute("data-bs-toggle","collapse");
    btn.setAttribute("data-bs-target","#others");
    btn.textContent="顯示其餘 "+(okUp.length+down.length)+" 台(無問題/無法連線)";
    const sub=document.createElement("div"); sub.className="collapse"; sub.id="others";
    okUp.concat(down).forEach(r=>sub.appendChild(hostCard(r,false)));
    box.appendChild(btn); box.appendChild(sub);
  }
}

function hostCard(r,isVuln){
  const d=document.createElement("div");
  d.className="card mb-3 shadow-sm"+(isVuln?" host-vuln":"");
  let badges="";
  if(!r.reachable) badges+=' <span class="badge text-bg-secondary">無法連線</span>';
  else{
    if(r.anonymous) badges+=' <span class="badge text-bg-warning">匿名登入</span>';
    if(r.weak_creds.length) badges+=' <span class="badge text-bg-danger">弱密碼</span>';
    if(!r.anonymous&&!r.weak_creds.length) badges+=' <span class="badge text-bg-success">正常</span>';
  }
  let html='<div class="card-body">';
  html+='<h5 class="card-title mono fs-6 mb-2">'+esc(r.host)+":"+r.port+badges+'</h5>';
  if(r.error) html+='<div class="text-secondary small">'+esc(r.error)+'</div>';
  if(r.weak_creds.length)
    html+='<div class="mono small text-danger mb-1">弱密碼:'+r.weak_creds.map(esc).join("　")+'</div>';
  if(r.anonymous||r.weak_creds.length)
    html+='<div class="small text-secondary">'+
      '<i class="bi bi-file-earmark-pdf"></i> PDF <b class="text-body">'+r.pdf_count+'</b> 個　'+
      '<i class="bi bi-image"></i> 圖片 <b class="text-body">'+r.image_count+'</b> 個'+
      (r.dmode?'　<span class="badge text-bg-secondary">資料連線:'+esc(r.dmode)+'</span>':'')+'</div>';
  html+='</div>';
  d.innerHTML=html;

  if(r.files&&r.files.length){
    const fl=document.createElement("div");
    fl.className="card-body border-top pt-3 d-flex flex-wrap gap-2";
    r.files.forEach(f=>{
      const el=document.createElement("div");
      el.className="file-chip d-inline-flex align-items-center gap-2 border rounded px-2 py-1 small";
      const ic=f.kind==="pdf"?'<i class="bi bi-file-earmark-pdf text-danger"></i>'
                             :'<i class="bi bi-image text-info"></i>';
      el.innerHTML=ic+'<span class="nm" title="'+esc(f.path)+'">'+esc(f.name)+'</span>'+
        '<span class="text-secondary">'+fmtSize(f.size)+'</span>'+
        '<button class="btn btn-sm btn-outline-info py-0 px-2" data-prev>預覽</button>'+
        '<a class="btn btn-sm btn-outline-secondary py-0 px-2" href="/download/'+jobId+'/'+f.id+'">下載</a>';
      el.querySelector("[data-prev]").onclick=()=>openPreview(f.id,f.kind,f.name);
      fl.appendChild(el);
    });
    d.appendChild(fl);
  }
  return d;
}

function openPreview(id,kind,name){
  $("#mName").textContent=name;
  const url="/preview/"+jobId+"/"+id;
  $("#mBody").innerHTML = kind==="pdf"
    ? '<iframe src="'+url+'"></iframe>'
    : '<img src="'+url+'" alt="preview">';
  previewModal.show();
}
</script>
</body>
</html>"""


# ------------------------- 進入點 -------------------------
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='FTP 資安稽核 Web 工具')
    ap.add_argument('--host', default='127.0.0.1', help='Web 服務綁定位址 (預設 127.0.0.1;對外請用 0.0.0.0)')
    ap.add_argument('--port', type=int, default=8000, help='Web 服務埠 (預設 8000)')
    args = ap.parse_args()
    print('FTP 稽核 Web 介面啟動於 http://%s:%d' % (args.host, args.port))
    print('提醒:僅限對已獲授權之主機進行稽核。')
    app.run(host=args.host, port=args.port, threaded=True)
