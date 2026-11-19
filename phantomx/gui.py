"""PHANTOMX control panel (black & white theme).

Long operations run in a worker thread; the worker only puts messages on a queue and the
Tk main thread drains it (Tk is not thread-safe)."""
from __future__ import annotations

import queue
import tempfile
import threading
import time
import tkinter as tk
import traceback
from dataclasses import replace
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, browser
from .branding import APP, AUTHOR, AUTHOR_URL, COPYRIGHT, DISCLAIMER, LOGO, REPO_URL
from .config import save_settings
from .engine import Engine, Status
from .leakcheck import FAIL, PASS, WARN, CheckResult, verdict

# ---- palette: black & white; red only for real danger ----
BG = "#000000"
CARD = "#0e0e0e"
RAISED = "#161616"
LINE = "#2a2a2a"
TEXT = "#ffffff"
SUB = "#a6a6a6"
FAINT = "#5a5a5a"
DANGER = "#ff3b3b"
FONT = "Segoe UI"
MONO = "Consolas"
CRASH_LOG = Path(tempfile.gettempdir()) / "phantomx-gui-error.log"
GUI_LOG = Path(tempfile.gettempdir()) / "phantomx-gui.log"
WATCH_MS = 15000


class FlatButton(tk.Label):
    """Flat button with hover state. Variants: primary (white), outline, ghost (dark)."""

    STYLES = {
        #           bg      fg     border   hover_bg  hover_fg  hover_border
        "primary": (TEXT, BG, TEXT, "#d6d6d6", BG, "#d6d6d6"),
        "outline": (BG, TEXT, TEXT, TEXT, BG, TEXT),
        "ghost": (RAISED, TEXT, LINE, "#232323", TEXT, SUB),
    }

    def __init__(self, parent, text, command, variant="ghost", size=11, pady=11):
        self.style = self.STYLES[variant]
        bg, fg, border = self.style[:3]
        super().__init__(parent, text=text, bg=bg, fg=fg, font=(FONT, size, "bold" if variant == "primary" else "normal"),
                         padx=14, pady=pady, cursor="hand2", highlightthickness=1,
                         highlightbackground=border, highlightcolor=border)
        self.command = command
        self.enabled = True
        self.bind("<Enter>", lambda e: self._paint(True))
        self.bind("<Leave>", lambda e: self._paint(False))
        self.bind("<ButtonRelease-1>", self._click)

    def _paint(self, hover: bool) -> None:
        bg, fg, border, hbg, hfg, hborder = self.style
        if not self.enabled:
            self.configure(bg=bg if bg != TEXT else RAISED, fg=FAINT, highlightbackground=LINE, cursor="arrow")
            return
        self.configure(bg=hbg if hover else bg, fg=hfg if hover else fg,
                       highlightbackground=hborder if hover else border, cursor="hand2")

    def _click(self, _event) -> None:
        if self.enabled and self.command:
            self.command()

    def set_enabled(self, on: bool) -> None:
        self.enabled = on
        self._paint(False)


class Link(tk.Label):
    def __init__(self, parent, text, url, size=9, fg=SUB):
        super().__init__(parent, text=text, bg=parent["bg"], fg=fg, font=(FONT, size), cursor="hand2")
        self.base_fg = fg
        self.bind("<Enter>", lambda e: self.configure(fg=TEXT, font=(FONT, size, "underline")))
        self.bind("<Leave>", lambda e: self.configure(fg=self.base_fg, font=(FONT, size)))
        self.bind("<ButtonRelease-1>", lambda e: browser.open_url(url) if isinstance(url, str) else url())


def _logo(parent, small: bool = False) -> tk.Label:
    """The PhantomX wordmark (white, transparent PNG); falls back to the ASCII logo."""
    try:
        import base64
        from importlib import resources
        name = "assets/logo-white-small.png" if small else "assets/logo-white.png"
        data = resources.files("phantomx").joinpath(name).read_bytes()
        img = tk.PhotoImage(data=base64.b64encode(data))
        label = tk.Label(parent, image=img, bg=parent["bg"], anchor="w")
        label.image = img  # keep a reference, or Tk drops the image
        return label
    except Exception:  # noqa: BLE001 - never let branding break the app
        return tk.Label(parent, text=LOGO, bg=parent["bg"], fg=TEXT, font=(MONO, 8 if small else 9),
                        justify="left", anchor="w")


def _card(parent, **kw) -> tk.Frame:
    return tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=LINE, **kw)


def _caption(parent, text) -> tk.Label:
    return tk.Label(parent, text=text.upper(), bg=parent["bg"], fg=FAINT, font=(FONT, 8, "bold"), anchor="w")


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.engine = Engine(log=lambda m: self.q.put(("log", m)))
        self.busy = False
        self.shown = ""
        root.title(f"{APP}  -  by {AUTHOR}")
        root.minsize(820, 560)
        root.configure(bg=BG)
        self._style_ttk()
        self._build()
        root.after(100, self._poll)
        root.after(WATCH_MS, self._watch)
        root.after(300, self._first_run_terms)
        self._run("status", self.engine.status)

    # ---------- layout ----------
    def _style_ttk(self):
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Mono.Horizontal.TProgressbar", troughcolor=RAISED, background=TEXT,
                    bordercolor=RAISED, lightcolor=TEXT, darkcolor=TEXT, thickness=4)

    def _build(self):
        wrap = tk.Frame(self.root, bg=BG, padx=24, pady=18)
        wrap.pack(fill="both", expand=True)

        # header
        head = tk.Frame(wrap, bg=BG)
        head.pack(fill="x")
        _logo(head).pack(side="left", anchor="w")
        meta = tk.Frame(head, bg=BG)
        meta.pack(side="right", anchor="ne")
        tk.Label(meta, text=f"v{__version__}", bg=BG, fg=SUB, font=(MONO, 9), padx=8, pady=2,
                 highlightthickness=1, highlightbackground=LINE).pack(anchor="e")
        tk.Label(meta, text=f"by {AUTHOR}", bg=BG, fg=TEXT, font=(FONT, 10, "bold")).pack(anchor="e", pady=(8, 0))
        Link(meta, "github.com/m911x0", AUTHOR_URL).pack(anchor="e")
        tk.Label(wrap, text="Whole-device Tor routing  /  fail-closed firewall lock  /  real leak tests",
                 bg=BG, fg=SUB, font=(FONT, 9), anchor="w").pack(fill="x", pady=(6, 14))

        # status card
        card = _card(wrap, padx=18, pady=16)
        card.pack(fill="x")
        top = tk.Frame(card, bg=CARD)
        top.pack(fill="x")
        self.pill = tk.Label(top, text="", font=(FONT, 9, "bold"), padx=10, pady=3)
        self.pill.pack(side="left")
        self.status_lbl = tk.Label(top, text="...", bg=CARD, fg=TEXT, font=(FONT, 15, "bold"), anchor="w")
        self.status_lbl.pack(side="left", padx=(12, 0))
        self.detail_lbl = tk.Label(card, text="", bg=CARD, fg=SUB, font=(FONT, 10), anchor="w",
                                   justify="left", wraplength=760)
        self.detail_lbl.pack(fill="x", pady=(10, 10))
        self.progress = ttk.Progressbar(card, maximum=100, style="Mono.Horizontal.TProgressbar")
        self.progress.pack(fill="x")

        # primary actions
        row1 = tk.Frame(wrap, bg=BG)
        row1.pack(fill="x", pady=(14, 8))
        row1.columnconfigure((0, 1), weight=1, uniform="a")
        self.btn_start = FlatButton(row1, "START PROTECTION", lambda: self._run("start", self._start_flow), "primary", 12, 13)
        self.btn_start.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.btn_stop = FlatButton(row1, "STOP & RESTORE INTERNET", self._confirm_stop, "outline", 12, 13)
        self.btn_stop.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        # secondary actions
        grid = tk.Frame(wrap, bg=BG)
        grid.pack(fill="x")
        grid.columnconfigure((0, 1, 2), weight=1, uniform="b")
        specs = [
            ("Leak test", lambda: self._run("check", self.engine.run_checks)),
            ("New identity", lambda: self._run("newnym", self.engine.new_identity)),
            ("Settings", self._settings_dialog),
            ("Open Tor Browser", self._open_tb),
            ("Install Tor Browser", lambda: self._run("install_tb", self._install_tb_flow)),
            ("Update components", lambda: self._run("install", self._install_flow)),
        ]
        self.secondary = []
        for i, (label, cmd) in enumerate(specs):
            b = FlatButton(grid, label, cmd, "ghost", 10, 9)
            b.grid(row=i // 3, column=i % 3, sticky="ew", padx=(0 if i % 3 == 0 else 4, 0 if i % 3 == 2 else 4), pady=4)
            self.secondary.append(b)
        self.btn_tb = self.secondary[3]
        self.buttons = [self.btn_start, self.btn_stop] + [b for b in self.secondary if b is not self.btn_tb]

        # results + log
        _caption(wrap, "Leak test").pack(fill="x", pady=(14, 4))
        self.checks = _card(wrap, padx=14, pady=10)
        self.checks.pack(fill="x")
        tk.Label(self.checks, text="No test run yet.", bg=CARD, fg=FAINT, font=(FONT, 10), anchor="w").pack(fill="x")

        # footer: packed at the bottom BEFORE the expanding log, so it is never squeezed out
        foot = tk.Frame(wrap, bg=BG)
        foot.pack(fill="x", side="bottom", pady=(12, 0))
        self._footer(foot)

        _caption(wrap, "Activity").pack(fill="x", pady=(14, 4))
        logbox = _card(wrap)
        logbox.pack(fill="both", expand=True)
        self.log = tk.Text(logbox, height=4, bg=CARD, fg=SUB, relief="flat", font=(MONO, 9), wrap="word",
                           padx=12, pady=8, insertbackground=TEXT, selectbackground="#333333", borderwidth=0)
        self.log.pack(fill="both", expand=True)

    def _footer(self, foot):
        tk.Label(foot, text=f"(c) 2026 {AUTHOR}  /  MIT License  /  Lawful use only", bg=BG, fg=FAINT,
                 font=(FONT, 9)).pack(side="left")
        Link(foot, "About & legal", self._about).pack(side="right")
        tk.Label(foot, text="  /  ", bg=BG, fg=FAINT, font=(FONT, 9)).pack(side="right")
        Link(foot, "Star PHANTOMX on GitHub", REPO_URL, fg=TEXT).pack(side="right")

    def _set_buttons(self, on: bool):
        for b in self.buttons:
            b.set_enabled(on)

    # ---------- dialogs ----------
    def _dialog(self, title: str, w: int, h: int) -> tk.Toplevel:
        win = tk.Toplevel(self.root, bg=BG, padx=22, pady=18)
        win.title(title)
        win.geometry(f"{w}x{h}+{self.root.winfo_rootx() + 60}+{self.root.winfo_rooty() + 40}")
        win.transient(self.root)
        return win

    def _about(self):
        win = self._dialog(f"About {APP}", 640, 560)
        _logo(win, small=True).pack(fill="x")
        tk.Label(win, text=f"{APP} v{__version__}", bg=BG, fg=TEXT, font=(FONT, 13, "bold"), anchor="w").pack(fill="x", pady=(12, 0))
        row = tk.Frame(win, bg=BG)
        row.pack(fill="x", pady=(4, 0))
        tk.Label(row, text=f"Created by {AUTHOR}  -  ", bg=BG, fg=SUB, font=(FONT, 10)).pack(side="left")
        Link(row, AUTHOR_URL, AUTHOR_URL, 10).pack(side="left")
        row2 = tk.Frame(win, bg=BG)
        row2.pack(fill="x")
        tk.Label(row2, text="Source code  -  ", bg=BG, fg=SUB, font=(FONT, 10)).pack(side="left")
        Link(row2, REPO_URL, REPO_URL, 10).pack(side="left")
        tk.Label(win, text=COPYRIGHT, bg=BG, fg=SUB, font=(FONT, 9), anchor="w").pack(fill="x", pady=(10, 0))
        _caption(win, "Lawful use & disclaimer").pack(fill="x", pady=(16, 4))
        box = _card(win, padx=14, pady=12)
        box.pack(fill="both", expand=True)
        tk.Label(box, text=DISCLAIMER, bg=CARD, fg=SUB, font=(FONT, 9), justify="left", anchor="nw",
                 wraplength=560).pack(fill="both", expand=True)
        FlatButton(win, "CLOSE", win.destroy, "outline", 10, 8).pack(fill="x", pady=(14, 0))

    def _first_run_terms(self):
        try:
            if self.engine.settings().terms_accepted:
                return
        except Exception:  # noqa: BLE001 - unreadable config: show the notice anyway
            pass
        win = self._dialog(f"{APP} - Lawful use", 600, 430)
        win.protocol("WM_DELETE_WINDOW", self.root.destroy)
        win.grab_set()
        tk.Label(win, text="Before you continue", bg=BG, fg=TEXT, font=(FONT, 14, "bold"), anchor="w").pack(fill="x")
        tk.Label(win, text=DISCLAIMER, bg=BG, fg=SUB, font=(FONT, 10), justify="left", anchor="w",
                 wraplength=550).pack(fill="x", pady=(10, 16))
        row = tk.Frame(win, bg=BG)
        row.pack(fill="x", side="bottom")
        row.columnconfigure((0, 1), weight=1, uniform="t")

        def accept():
            try:
                self.engine.ops.secure_root(self.engine.layout.root)
                s = self.engine.settings()
                s.terms_accepted = True
                save_settings(self.engine.layout.config, s)
            except Exception as exc:  # noqa: BLE001
                self.engine.log(f"Could not save acceptance: {exc}")
            win.grab_release()
            win.destroy()
        FlatButton(row, "I AGREE - LAWFUL USE ONLY", accept, "primary", 10, 10).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        FlatButton(row, "EXIT", self.root.destroy, "outline", 10, 10).grid(row=0, column=1, sticky="ew", padx=(5, 0))

    # ---------- worker plumbing ----------
    def _watch(self):
        """While protected, verify every few seconds that sing-box and tor are still alive."""
        if not self.busy and self.shown in ("protected", "protected_warn", "unverified"):
            def work():
                try:
                    st = self.engine.status()
                    tail = "" if st.phase == "running" else self.engine.sb.log_tail(5) + "\n" + self.engine.tor.log_tail(3)
                    self.q.put(("watch", st, tail))
                except Exception as exc:  # noqa: BLE001
                    self.q.put(("log", f"watchdog: {exc}"))
            threading.Thread(target=work, daemon=True).start()
        self.root.after(WATCH_MS, self._watch)

    def _progress(self, pct: int):
        self.q.put(("progress", pct))

    def _download_progress(self, name: str, done: int, total: int):
        if total:
            self.q.put(("dl", name, int(done * 100 / total)))

    def _install_flow(self):
        from . import installer
        installer.install_auto(self.engine.layout, self.engine.ops, self.engine.log, self._download_progress)

    def _install_tb_flow(self):
        from . import installer
        return installer.install_tor_browser(self.engine.layout, self.engine.ops, self.engine.log,
                                             self._download_progress)

    def _start_flow(self):
        from . import installer
        if not installer.is_installed(self.engine.layout):
            self.engine.log("First run: downloading and verifying tor + sing-box...")
            self._install_flow()
        return self.engine.start(self._progress)

    def _run(self, name, fn, *args):
        if self.busy:
            return
        self.busy = True
        self._set_buttons(False)
        if name == "start":
            self._show_status("starting")

        def work():
            try:
                self.q.put(("done", name, fn(*args), None))
            except Exception as exc:  # noqa: BLE001 - shown to the user
                self.q.put(("done", name, None, exc))
        threading.Thread(target=work, daemon=True).start()

    def _log(self, text: str):
        self.log.insert("end", f"{time.strftime('%H:%M:%S')}  {text}\n")
        self.log.see("end")

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "log":
                    self._log(msg[1])
                elif msg[0] == "progress":
                    self.progress["value"] = msg[1]
                    self.detail_lbl.configure(text=f"Connecting to the Tor network: {msg[1]}%")
                elif msg[0] == "watch":
                    st, tail = msg[1], msg[2]
                    if st.phase != "running" and self.shown in ("protected", "protected_warn", "unverified"):
                        self._show_engine_status(st)
                        self._log("WARNING: a tunnel component stopped "
                                  f"(sing-box alive={st.singbox_alive}, tor alive={st.tor_alive}). "
                                  f"The device is locked (no leak). Last log lines:\n{tail}")
                elif msg[0] == "dl":
                    self.progress["value"] = msg[2]
                    self.detail_lbl.configure(text=f"Downloading {msg[1]}: {msg[2]}%")
                elif msg[0] == "done":
                    self.busy = False
                    self._set_buttons(True)
                    self._done(*msg[1:])
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _done(self, name, result, err):
        if err is not None:
            self._log(f"ERROR: {err}")
            if name == "start":
                self._run("status", self.engine.status)
            messagebox.showerror(APP, str(err))
            return
        if name == "status":
            self._show_engine_status(result)
        elif name in ("start", "check"):
            self._render_checks(result)
            self._show_status({PASS: "protected", WARN: "protected_warn", FAIL: "leak"}[verdict(result)])
        elif name == "stop":
            self.progress["value"] = 0
            self._show_status("off")
        elif name == "install":
            self.progress["value"] = 100
            self.detail_lbl.configure(text="Components installed and verified.")
        elif name == "install_tb":
            self.progress["value"] = 100
            self.detail_lbl.configure(text=f"Tor Browser ready at {result}. Use 'Open Tor Browser'.")

    # ---------- views ----------
    def _show_engine_status(self, st: Status):
        if st.phase == "running":
            # PX07: "running" is not "protected". Only a passing leak test earns PROTECTED.
            self.progress["value"] = st.bootstrap
            key = {PASS: "protected", WARN: "protected_warn", FAIL: "leak"}.get(st.verified or "", "unverified")
            self._show_status(key)
            if key == "unverified":
                self.root.after(200, lambda: self._run("check", self.engine.run_checks))
        elif st.phase in ("locked", "locking"):
            self._show_status("locked")
        else:
            self._show_status("off")
        if st.notes:
            self.detail_lbl.configure(text=" | ".join(st.notes))

    def _show_status(self, key: str):
        # pill text, pill style (bg, fg), headline, detail
        pill, (pbg, pfg), headline, detail = {
            "off": ("OFF", (RAISED, SUB), "Protection is off",
                    "Your connection is normal and NOT hidden. Press START PROTECTION before you browse."),
            "starting": ("STARTING", (RAISED, TEXT), "Starting...",
                         "The device is locked first; nothing leaves until Tor is ready."),
            "locked": ("LOCKED", (BG, TEXT), "Locked - no internet, no leaks",
                       "Press START PROTECTION to retry, or STOP & RESTORE INTERNET to go back to normal."),
            "unverified": ("VERIFYING", (RAISED, TEXT), "Tunnel running - verifying...",
                           "Running a leak test before claiming protection. Do not browse until it passes."),
            "protected": ("PROTECTED", (TEXT, BG), "All device traffic goes through Tor",
                          "For sensitive browsing use Tor Browser only: normal browsers reveal who you are even when your IP is hidden."),
            "protected_warn": ("PROTECTED", (TEXT, BG), "Protected, with warnings",
                               "See the leak test results below."),
            "leak": ("LEAK", (DANGER, TEXT), "Leak test failed - do not browse now",
                     "See the leak test results below."),
        }[key]
        self.shown = key
        self.pill.configure(text=pill, bg=pbg, fg=pfg, highlightthickness=1,
                            highlightbackground=TEXT if key == "locked" else pbg)
        self.status_lbl.configure(text=headline, fg=DANGER if key == "leak" else TEXT)
        self.detail_lbl.configure(text=detail)

    def _render_checks(self, results: list[CheckResult]):
        for w in self.checks.winfo_children():
            w.destroy()
        marks = {PASS: ("OK", TEXT), WARN: ("!!", SUB), FAIL: ("XX", DANGER)}
        for r in results:
            mark, color = marks[r.status]
            row = tk.Frame(self.checks, bg=CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=mark, bg=CARD, fg=color, font=(MONO, 9, "bold"), width=3, anchor="w").pack(side="left", anchor="n")
            body = r.title + (f"  -  {r.detail}" if r.detail else "")
            tk.Label(row, text=body, bg=CARD, fg=TEXT if r.status != FAIL else DANGER, font=(FONT, 10),
                     anchor="w", justify="left", wraplength=720).pack(side="left", fill="x")

    # ---------- actions ----------
    def _confirm_stop(self):
        if messagebox.askyesno(APP, "Your connection will be normal and exposed again. Continue?"):
            self._run("stop", self.engine.stop)

    def _open_tb(self):
        try:
            settings = self.engine.settings()
            if not settings.tor_browser_dir:
                from .installer import find_tor_browser
                found = find_tor_browser(self.engine.layout.os)
                if found:
                    settings.tor_browser_dir = str(found)
                    save_settings(self.engine.layout.config, settings)
                    self.engine.log(f"Found Tor Browser at {found}; saved in Settings.")
            browser.launch(settings.tor_browser_dir)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Tor Browser", str(exc))

    def _settings_dialog(self):
        try:
            s = self.engine.settings()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Settings", str(exc))
            return
        win = self._dialog(f"{APP} - Settings", 740, 760)

        def lbl(text, fg=TEXT, size=11, bold=True, pady=(12, 4)):
            tk.Label(win, text=text, font=(FONT, size, "bold" if bold else "normal"), fg=fg, bg=BG,
                     anchor="w", justify="left", wraplength=690).pack(fill="x", pady=pady)

        def entry_style(w):
            w.configure(bg=CARD, fg=TEXT, insertbackground=TEXT, relief="flat", highlightthickness=1,
                        highlightbackground=LINE, highlightcolor=TEXT)

        check_kw = dict(bg=BG, fg=TEXT, selectcolor=CARD, activebackground=BG, activeforeground=TEXT,
                        anchor="w", font=(FONT, 10), highlightthickness=0)

        lbl("Tor Browser folder", pady=(0, 4))
        tb_var = tk.StringVar(value=s.tor_browser_dir)
        row = tk.Frame(win, bg=BG)
        row.pack(fill="x")
        e = tk.Entry(row, textvariable=tb_var, font=(FONT, 10))
        entry_style(e)
        e.pack(side="left", fill="x", expand=True, ipady=7)
        FlatButton(row, "Browse", lambda: tb_var.set(filedialog.askdirectory(parent=win) or tb_var.get()),
                   "ghost", 10, 6).pack(side="left", padx=(8, 0))

        lbl("Privacy mode")
        mode_var = tk.StringVar(value=s.privacy_mode)
        for value, desc in (("balanced", "Balanced (faster) - shared circuits; verified Tor Browser skips Tor-over-Tor"),
                            ("strict", "Strict (slower) - new circuit per destination; Tor Browser runs Tor-over-Tor")):
            tk.Radiobutton(win, text=desc, value=value, variable=mode_var, **check_kw).pack(fill="x")

        lbl("Apps that bypass Tor (split tunnel)")
        lbl("These apps use your REAL IP. Never add a browser or anything you want hidden.", DANGER, 9, False, (0, 6))
        apps_row = tk.Frame(win, bg=BG)
        apps_row.pack(fill="x")
        apps_list = tk.Listbox(apps_row, height=3, font=(MONO, 9), selectbackground="#333333", activestyle="none")
        entry_style(apps_list)
        apps_list.pack(side="left", fill="x", expand=True)
        for a in s.bypass_apps:
            apps_list.insert("end", a)

        def add_app():
            types = [("Programs", "*.exe")] if self.engine.layout.os == "windows" else [("All files", "*")]
            path = filedialog.askopenfilename(parent=win, title="Choose an app to bypass Tor", filetypes=types)
            if not path:
                return
            if any(b in path.lower() for b in ("firefox", "chrome", "msedge", "brave", "opera", "tor browser", "safari")):
                if not messagebox.askyesno("Bypass", "This looks like a browser. Browsing outside Tor exposes "
                                           "your real IP. Add it anyway?", parent=win):
                    return
            apps_list.insert("end", path)
        btns = tk.Frame(apps_row, bg=BG)
        btns.pack(side="left", padx=(8, 0), fill="y")
        FlatButton(btns, "Add", add_app, "ghost", 10, 5).pack(fill="x")
        FlatButton(btns, "Remove", lambda: [apps_list.delete(i) for i in reversed(apps_list.curselection())],
                   "ghost", 10, 5).pack(fill="x", pady=(6, 0))

        lbl("Bridges")
        bridges_var = tk.BooleanVar(value=s.use_bridges)
        tk.Checkbutton(win, text="Use bridges - enable only if Tor is blocked in your country",
                       variable=bridges_var, **check_kw).pack(fill="x")
        lbl("Paste bridge lines (from bridges.torproject.org or Tor Browser's settings):", SUB, 9, False, (4, 4))
        text = tk.Text(win, height=7, font=(MONO, 9), padx=8, pady=6)
        entry_style(text)
        text.pack(fill="both", expand=True)
        text.insert("1.0", "\n".join(s.bridges))

        def save():
            lines = [l.strip() for l in text.get("1.0", "end").splitlines() if l.strip()]
            try:
                from .config import normalize_app_path
                from .torconf import bridge_lines
                apps = [normalize_app_path(a) for a in apps_list.get(0, "end")]
                new = replace(s, tor_browser_dir=tb_var.get().strip(), privacy_mode=mode_var.get(),
                              bypass_apps=apps, use_bridges=bridges_var.get(), bridges=lines)
                bridge_lines(new)
                save_settings(self.engine.layout.config, new)
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("Settings", str(exc), parent=win)
                return
            messagebox.showinfo("Settings", "Saved. Changes apply on the next start.", parent=win)
            win.destroy()
        FlatButton(win, "SAVE", save, "primary", 11, 10).pack(fill="x", pady=(14, 0))


def _gui_log(msg: str) -> None:
    try:
        with open(GUI_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except OSError:
        pass


def _place_and_show(root: tk.Tk, w: int = 900, h: int = 860) -> None:
    """Center on the primary screen, un-minimize, and force to the foreground (an elevated
    window started from a console is often created behind it or without focus)."""
    root.update_idletasks()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    h = min(h, max(560, sh - 70))
    x, y = max(0, (sw - w) // 2), max(0, (sh - h) // 2 - 20)
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.deiconify()
    root.lift()
    root.attributes("-topmost", True)
    root.after(800, lambda: root.attributes("-topmost", False))
    root.focus_force()
    try:
        import ctypes
        user32 = ctypes.windll.user32
        hwnd = int(root.wm_frame(), 16)
        user32.ShowWindow(hwnd, 9)          # SW_RESTORE
        user32.SetForegroundWindow(hwnd)
        user32.FlashWindow(hwnd, True)
    except (AttributeError, OSError, ValueError):
        pass


def _log_window_state(root: tk.Tk) -> None:
    try:
        _gui_log(f"window: state={root.state()} mapped={root.winfo_ismapped()} viewable={root.winfo_viewable()} "
                 f"geometry={root.winfo_geometry()} screen={root.winfo_screenwidth()}x{root.winfo_screenheight()} "
                 f"frame={root.wm_frame()}")
    except tk.TclError as exc:
        _gui_log(f"window state error: {exc}")


def run_gui() -> None:
    try:
        from .system import is_admin
        _gui_log(f"--- GUI start (admin={is_admin()})")
        root = tk.Tk()
        App(root)
        _place_and_show(root)
        root.after(1500, lambda: _log_window_state(root))
        _gui_log("entering mainloop")
        print("Control panel is open. If you don't see it, check the taskbar. Close the window to exit.")
        root.mainloop()
        _gui_log("mainloop ended (window closed)")
    except Exception:
        CRASH_LOG.write_text(traceback.format_exc(), encoding="utf-8")
        try:
            messagebox.showerror(APP, f"The GUI crashed. Details saved to:\n{CRASH_LOG}")
        except Exception:  # noqa: BLE001
            pass
        raise
