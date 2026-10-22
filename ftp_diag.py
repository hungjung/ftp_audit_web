#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP 診斷腳本 —— 當 Web 工具檔案計數為 0 時,用這支對「單一台」伺服器直接檢視
伺服器實際回傳的目錄列表格式,把輸出整段貼回給開發者即可精準修正。

用法:
  python3 ftp_diag.py <host> <user> <password> [port]
  python3 ftp_diag.py 192.168.1.10 ftpuser ftpuser
  python3 ftp_diag.py 192.168.1.10 anonymous anonymous@example.com 21

只讀取目錄列表,不下載、不修改任何檔案。
"""
import ftplib
import sys


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    host = sys.argv[1]
    user = sys.argv[2]
    pwd = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 21

    f = ftplib.FTP()
    f.encoding = 'latin-1'
    print("連線 %s:%d ..." % (host, port))
    f.connect(host, port, timeout=10)
    print("登入 %s ..." % user)
    f.login(user, pwd)
    print("登入成功\n" + "=" * 60)

    # 伺服器支援的功能
    try:
        print("[FEAT 伺服器支援功能]")
        print(f.sendcmd('FEAT'))
    except Exception as e:
        print("  FEAT 失敗:", e)
    print("=" * 60)

    # 登入後所在目錄
    try:
        cwd = f.pwd()
        print("[PWD 登入後目錄] =", repr(cwd))
    except Exception as e:
        cwd = '/'
        print("  PWD 失敗:", e)
    print("=" * 60)

    # MLSD
    print("[MLSD 原始輸出]")
    try:
        n = 0
        for name, facts in f.mlsd(cwd):
            print("  name=%-30r facts=%s" % (name, facts))
            n += 1
            if n >= 30:
                print("  ...(僅顯示前 30 筆)")
                break
        if n == 0:
            print("  (MLSD 回傳空白)")
    except Exception as e:
        print("  MLSD 不支援或失敗:", repr(e))
    print("=" * 60)

    # LIST(目前目錄,無參數)
    print("[LIST(無參數,CWD 當前目錄)原始輸出]")
    try:
        lines = []
        f.retrlines('LIST', lines.append)
        for l in lines[:40]:
            print("  |" + l)
        if not lines:
            print("  (LIST 回傳空白)")
    except Exception as e:
        print("  LIST 失敗:", repr(e))
    print("=" * 60)

    # LIST(帶絕對路徑)
    print("[LIST %s(帶路徑)原始輸出]" % cwd)
    try:
        lines = []
        f.retrlines('LIST ' + cwd, lines.append)
        for l in lines[:40]:
            print("  |" + l)
        if not lines:
            print("  (帶路徑的 LIST 回傳空白 ← 可能是重點)")
    except Exception as e:
        print("  帶路徑 LIST 失敗:", repr(e))
    print("=" * 60)

    # NLST
    print("[NLST 原始輸出]")
    try:
        names = f.nlst(cwd)
        for x in names[:40]:
            print("  |" + repr(x))
        if not names:
            print("  (NLST 回傳空白)")
    except Exception as e:
        print("  NLST 失敗:", repr(e))
    print("=" * 60)

    f.quit()
    print("診斷完成。請把以上整段輸出貼回。")


if __name__ == '__main__':
    main()
