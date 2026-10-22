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
import re
import socket
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

    # LIST(被動模式 PASV,ftplib 預設)
    print("[LIST — 被動模式 PASV(ftplib 預設)]")
    f.set_pasv(True)
    try:
        lines = []
        f.retrlines('LIST', lines.append)
        for l in lines[:40]:
            print("  |" + l)
        if not lines:
            print("  (LIST 回傳空白)")
    except Exception as e:
        print("  被動模式 LIST 失敗:", repr(e))
    print("=" * 60)

    # 被動模式:挖出伺服器回報的 PASV 位址,並測試資料埠可達性
    print("[PASV 位址分析]")
    control_ip = None
    try:
        control_ip = f.sock.getpeername()[0]
        print("  控制連線實際 IP =", control_ip)
    except Exception as e:
        print("  取得控制 IP 失敗:", e)
    adv_ip, adv_port = None, None
    try:
        resp = f.sendcmd('PASV')
        print("  PASV 原始回應 =", resp)
        mobj = re.search(r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', resp)
        if mobj:
            nums = list(map(int, mobj.groups()))
            adv_ip = '%d.%d.%d.%d' % tuple(nums[:4])
            adv_port = nums[4] * 256 + nums[5]
            print("  伺服器回報資料位址 =", adv_ip, "port", adv_port)
            if control_ip and adv_ip != control_ip:
                print("  ⚠ 回報位址與控制 IP 不同 → 可能是 NAT 誤報(改用控制 IP 或許可解)")
        for label, ip in (("回報位址", adv_ip), ("控制 IP", control_ip)):
            if not ip or not adv_port:
                continue
            s = socket.socket(); s.settimeout(6)
            r = s.connect_ex((ip, adv_port)); s.close()
            print("  TCP 連 %s %s:%d -> %s" % (label, ip, adv_port,
                  "可連" if r == 0 else "不可連 (errno %d)" % r))
    except Exception as e:
        print("  PASV 分析失敗:", repr(e))
    print("=" * 60)

    # LIST — 被動 + 改用控制連線 IP(修 NAT 誤報)
    print("[LIST — 被動模式 + 改用控制連線 IP]")
    try:
        class _OverrideFTP(ftplib.FTP):
            def makepasv(self):
                h, p = super().makepasv()
                return self.sock.getpeername()[0], p  # 忽略回報 IP,改用控制 IP
        f3 = _OverrideFTP(); f3.encoding = 'latin-1'
        f3.connect(host, port, timeout=10); f3.login(user, pwd); f3.set_pasv(True)
        lines = []
        f3.retrlines('LIST', lines.append)
        for l in lines[:40]:
            print("  |" + l)
        print("  → 此法%s" % ("成功!(工具會自動採用)" if lines else "回傳空白"))
        f3.quit()
    except Exception as e:
        print("  被動+控制IP LIST 失敗:", repr(e))
    print("=" * 60)

    # LIST — 主動模式 PORT
    print("[LIST — 主動模式 PORT]")
    try:
        f2 = ftplib.FTP(); f2.encoding = 'latin-1'
        f2.connect(host, port, timeout=10); f2.login(user, pwd); f2.set_pasv(False)
        lines = []
        f2.retrlines('LIST', lines.append)
        for l in lines[:40]:
            print("  |" + l)
        print("  → 此法%s" % ("成功!" if lines else "回傳空白"))
        f2.quit()
    except Exception as e:
        print("  主動模式 LIST 失敗:", repr(e))
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

    try:
        f.quit()
    except Exception:
        try:
            f.close()
        except Exception:
            pass
    print("診斷完成。請把以上整段輸出貼回。")


if __name__ == '__main__':
    main()
