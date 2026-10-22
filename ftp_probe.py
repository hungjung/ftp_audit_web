#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP 列目錄『配方探測』腳本
----------------------------------------------------------------
目的:在你實際要使用工具的那台機器上,測出『哪一種列目錄做法』在你的
      伺服器上穩定可行,以便把主工具精準對齊,不再靠猜。

每種配方都用全新連線、各試 3 次,回報成功/失敗與抓到幾個項目。

用法:
  python3 ftp_probe.py <host> <user> <password> [port]
  python3 ftp_probe.py 140.116.245.108 1234 <密碼>
"""
import ftplib
import socket
import sys
import time


def new_conn(host, port, user, pwd, timeout=10):
    f = ftplib.FTP()
    f.encoding = 'latin-1'
    f.connect(host, port, timeout=timeout)
    f.login(user, pwd)
    return f


class CtrlIPFTP(ftplib.FTP):
    """被動模式改用控制連線 IP(忽略 227 回報位址)。"""
    def makepasv(self):
        h, p = super().makepasv()
        try:
            return self.sock.getpeername()[0], p
        except Exception:
            return h, p


def recipe_A(host, port, user, pwd):
    """預設被動 + 不帶參數 LIST(列當前目錄)。"""
    f = new_conn(host, port, user, pwd)
    f.set_pasv(True)
    try:
        lines = []
        f.retrlines('LIST', lines.append)
        return len(lines)
    finally:
        _q(f)


def recipe_B(host, port, user, pwd):
    """被動 + 控制IP覆寫 + 不帶參數 LIST(= diag 成功的做法)。"""
    f = CtrlIPFTP()
    f.encoding = 'latin-1'
    f.connect(host, port, timeout=10)
    f.login(user, pwd)
    f.set_pasv(True)
    try:
        lines = []
        f.retrlines('LIST', lines.append)
        return len(lines)
    finally:
        _q(f)


def recipe_C(host, port, user, pwd):
    """被動 + 先『預敲』資料埠(makepasv+connect+close)再 LIST。"""
    f = new_conn(host, port, user, pwd)
    f.set_pasv(True)
    try:
        try:
            h, p = f.makepasv()
            s = socket.create_connection((h, p), 10)
            s.close()
        except Exception:
            pass
        lines = []
        f.retrlines('LIST', lines.append)
        return len(lines)
    finally:
        _q(f)


def recipe_D(host, port, user, pwd):
    """被動 + 先 LIST(忽略首次 426)再 LIST 第二次(同一連線重試)。"""
    f = new_conn(host, port, user, pwd)
    f.set_pasv(True)
    try:
        for _ in range(3):
            try:
                lines = []
                f.retrlines('LIST', lines.append)
                return len(lines)
            except Exception:
                time.sleep(0.8)
        raise IOError('三次 LIST 皆失敗')
    finally:
        _q(f)


def _q(f):
    try:
        f.quit()
    except Exception:
        try:
            f.close()
        except Exception:
            pass


RECIPES = [
    ('A 預設被動+bare LIST', recipe_A),
    ('B 被動+控制IP(diag成功法)', recipe_B),
    ('C 被動+預敲資料埠', recipe_C),
    ('D 被動+同連線重試3次', recipe_D),
]


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    host, user, pwd = sys.argv[1], sys.argv[2], sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 21

    print("探測目標 %s:%d  帳號 %s" % (host, port, user))
    print("=" * 56)
    for name, fn in RECIPES:
        results = []
        for i in range(3):
            try:
                n = fn(host, port, user, pwd)
                results.append('成功(%d項)' % n)
            except Exception as e:
                results.append('失敗:%s' % (type(e).__name__))
            time.sleep(0.6)
        ok = sum(1 for r in results if r.startswith('成功'))
        print("%-26s  %d/3 成功  ->  %s" % (name, ok, ' | '.join(results)))
    print("=" * 56)
    print("請把以上整段貼回。哪一列穩定成功,就把主工具對齊那個做法。")


if __name__ == '__main__':
    main()
