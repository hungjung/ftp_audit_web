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


def ftp_connect(host, port, user, password, timeout):
    """建立並登入 FTP 連線(encoding 用 latin-1 避免檔名解碼錯誤)。"""
    ftp = ftplib.FTP()
    ftp.encoding = 'latin-1'
    ftp.connect(host, port, timeout=timeout)
    ftp.login(user, password)
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
    三層後備:MLSD → LIST 解析 → NLST + SIZE。"""
    # 1) MLSD(最佳:直接提供型別與大小)
    try:
        out = []
        for name, facts in ftp.mlsd(path or '/'):
            if name in ('.', '..'):
                continue
            typ = facts.get('type', '')
            if typ == 'dir':
                out.append((name, True, None))
            elif typ == 'file':
                sz = facts.get('size')
                out.append((name, False, int(sz) if sz and sz.isdigit() else None))
        if out:
            return out
    except Exception:
        pass
    # 2) LIST 解析(標準 ls -l / IIS 格式;最通用的後備)
    try:
        lines = []
        ftp.retrlines('LIST ' + (path or '/'), lines.append)
        out = []
        for ln in lines:
            r = _parse_list_line(ln)
            if r:
                out.append(r)
        if out:
            return out
    except Exception:
        pass
    # 3) 最後手段:NLST + SIZE(nlst 會把連線切回 ASCII,故每次 SIZE 前重設二進位)
    out = []
    try:
        names = ftp.nlst(path or '/')
    except Exception:
        return out
    for n in names:
        base = n.rsplit('/', 1)[-1]
        if base in ('.', '..'):
            continue
        full = n if n.startswith('/') else _join(path, base)
        sz, is_dir = None, False
        try:
            ftp.voidcmd('TYPE I')  # 重設二進位,否則 SIZE 在 ASCII 模式會被拒
            sz = ftp.size(full)
            is_dir = (sz is None)
        except Exception:
            # 無法判定:用副檔名輔助 — 有已知副檔名就當檔案,否則當目錄
            ext = os.path.splitext(base)[1].lower()
            is_dir = ext not in IMAGE_EXTS and ext not in PDF_EXTS
        out.append((base, is_dir, sz))
    return out


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
        for name, is_dir, size in _list_dir(ftp, path):
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
            found.append({'path': _join(path, name), 'name': name,
                          'ext': ext, 'kind': kind, 'size': size})
            if len(found) >= max_files:
                break
    return found


# ------------------------- 主機稽核 -------------------------
def audit_host(host, port, creds, timeout):
    res = {'host': host, 'port': port, 'reachable': False, 'anonymous': False,
           'weak_creds': [], 'login_user': None, 'login_pass': None,
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
            ftp = ftp_connect(host, port, working[0], working[1], timeout)
            try:
                files = walk_ftp(ftp)
            finally:
                _close(ftp)
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


def download_ftp_file(host, port, user, password, path, timeout, max_bytes):
    ftp = ftp_connect(host, port, user, password, timeout)
    buf = io.BytesIO()
    state = {'n': 0}

    def cb(data):
        state['n'] += len(data)
        if state['n'] > max_bytes:
            raise IOError('file exceeds preview limit')
        buf.write(data)

    try:
        ftp.voidcmd('TYPE I')
        ftp.retrbinary('RETR ' + path, cb)
    finally:
        _close(ftp)
    return buf.getvalue()


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
                                 f['path'], timeout=15, max_bytes=PREVIEW_MAX_BYTES)
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
      '<i class="bi bi-image"></i> 圖片 <b class="text-body">'+r.image_count+'</b> 個</div>';
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
