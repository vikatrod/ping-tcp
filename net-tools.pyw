#!/usr/bin/env python3
# net_tools_gui.pyw
"""
App com duas abas:
  1) DISCOVERY ICMP: quebra a rede em /24 e, para cada /24, acha o primeiro IP que responde ICMP (ping).
  2) TCP PING: realiza "pings" TCP (tentativa de conexão) para 1..N hosts/portas, mede latência.

Requisitos: Python 3.8+ (stdlib). No Windows, use .pyw ou pythonw.exe para não abrir console.
"""

import platform
import subprocess
import ipaddress
import threading
import csv
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from tkinter import (
    Tk, StringVar, IntVar, DoubleVar, ttk, Frame, Label, Entry, Button,
    scrolledtext, filedialog, messagebox
)
import tkinter as tk  # necessário para PhotoImage/Label usados no overlay

# ===================== Configuração Geral =====================
IS_WINDOWS = platform.system().lower().startswith("win")

# ICMP
PING_COUNT = 5             # pacotes por IP na aba ICMP
PING_TIMEOUT_MS = 1000     # timeout por pacote (ms)
DEFAULT_WORKERS_ICMP = 50  # quantos /24 simultâneos

# TCP
DEFAULT_WORKERS_TCP = 200      # conexões simultâneas
DEFAULT_TCP_TIMEOUT = 3.0      # segundos por tentativa
DEFAULT_TCP_INTERVAL = 1.0     # segundos entre tentativas por host (quando count>1)
DEFAULT_TCP_COUNT = 10         # tentativas por host/porta

# ===================== LOGO (BASE64) PARA OVERLAY NAS ÁREAS DE LOG =====================
# Use SOMENTE a parte Base64 (remova 'data:image/png;base64,').
BASE64_LOGO = (
    # Placeholder PNG pequeno (troque pelo seu Base64)
    "base64"
)

# ===================== Helpers ICMP =====================

def build_ping_command(ip: str, count: int = PING_COUNT):
    if IS_WINDOWS:
        return ["ping", "-n", str(count), "-w", str(PING_TIMEOUT_MS), ip]
    else:
        timeout_s = max(1, int((PING_TIMEOUT_MS + 999) // 1000))
        return ["ping", "-c", str(count), "-W", str(timeout_s), ip]

def run_ping_silent(cmd, count):
    """Executa ping sem abrir janela no Windows e retorna (returncode, stdout+stderr)."""
    run_kwargs = dict(
        capture_output=True,
        text=True,
        timeout=(count * (PING_TIMEOUT_MS / 1000.0) + 5),
        shell=False
    )
    if IS_WINDOWS:
        # esconde janelas do ping.exe
        run_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            run_kwargs["startupinfo"] = si
        except Exception:
            pass
    proc = subprocess.run(cmd, **run_kwargs)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

def parse_packet_loss(output: str):
    try:
        if IS_WINDOWS:
            for line in output.splitlines():
                if "Lost =" in line or "Perdidos" in line:
                    return line.strip()
        else:
            for line in output.splitlines():
                if "packet loss" in line:
                    parts = line.strip().split(",")
                    for p in parts:
                        if "packet loss" in p:
                            return p.strip()
    except Exception:
        pass
    return None

def ping_host_icmp(ip: str, count: int = PING_COUNT):
    cmd = build_ping_command(ip, count)
    try:
        rc, out = run_ping_silent(cmd, count)
        ok = (rc == 0)
        return {
            "ip": ip, "ok": ok, "returncode": rc,
            "packet_loss": parse_packet_loss(out),
            "output": out
        }
    except subprocess.TimeoutExpired as e:
        return {"ip": ip, "ok": False, "returncode": 124, "packet_loss": "timeout", "output": str(e)}
    except Exception as e:
        return {"ip": ip, "ok": False, "returncode": 1, "packet_loss": "error", "output": str(e)}

def scan_subnet_until_found(subnet: ipaddress.IPv4Network, stop_event: threading.Event):
    attempts = 0
    last_result = None
    for ip in subnet.hosts():
        if stop_event.is_set():
            return {"subnet": str(subnet.with_prefixlen), "found": False, "found_ip": None,
                    "attempts": attempts, "last_result": last_result, "cancelled": True}
        ip_str = str(ip)
        attempts += 1
        res = ping_host_icmp(ip_str, PING_COUNT)
        last_result = res
        if res.get("ok"):
            return {"subnet": str(subnet.with_prefixlen), "found": True, "found_ip": ip_str,
                    "attempts": attempts, "last_result": res, "cancelled": False}
    return {"subnet": str(subnet.with_prefixlen), "found": False, "found_ip": None,
            "attempts": attempts, "last_result": last_result, "cancelled": False}

# ===================== Helpers TCP =====================

def tcp_ping_once(host: str, port: int, timeout: float = DEFAULT_TCP_TIMEOUT):
    """
    Um 'ping TCP': tenta conectar TCP (SYN->SYN/ACK) e mede o tempo.
    Retorna dict com sucesso e rtt_ms (se sucesso).
    """
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            rtt = (time.perf_counter() - t0) * 1000.0
            return {"host": host, "port": port, "ok": True, "rtt_ms": rtt, "error": None}
    except Exception as e:
        rtt = (time.perf_counter() - t0) * 1000.0
        return {"host": host, "port": port, "ok": False, "rtt_ms": None, "error": str(e), "elapsed_ms": rtt}

def tcp_ping_target(host: str, ports: list[int], count: int, interval: float, timeout: float,
                    queue: Queue, stop_event: threading.Event):
    """
    Faz 'count' tentativas por porta e PUBLICA cada resultado em tempo real na fila.
    No final de cada porta envia um resumo ('summary').
    Retorna apenas o host processado (valor simbólico).
    """
    for port in ports:
        if stop_event.is_set():
            break

        success = 0
        rtts = []
        last_err = None

        for i in range(count):
            if stop_event.is_set():
                break
            res = tcp_ping_once(host, port, timeout)
            # publica a tentativa imediatamente
            queue.put(("attempt", res))

            if res["ok"]:
                success += 1
                rtts.append(res["rtt_ms"])
            else:
                last_err = res.get("error")

            if i < count - 1:
                time.sleep(max(0.0, interval))

        summary = {
            "type": "summary",
            "host": host,
            "port": port,
            "sent": count,
            "recv": success,
            "loss_pct": round(100.0 * (1.0 - (success / max(1, count))), 1),
            "min_ms": round(min(rtts), 2) if rtts else None,
            "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
            "max_ms": round(max(rtts), 2) if rtts else None,
            "last_error": last_err
        }
        # publica o resumo também
        queue.put(("summary", summary))

    return host

# ===================== Utilitários de Overlay (marca d'água no Text) =====================

# SUBSTITUA a função inteira por esta versão:
def attach_watermark_to_text(text_widget: tk.Text):
    """
    Coloca um Label com a imagem (PhotoImage) centralizado sobre o Text (overlay).
    Repassa eventos de scroll/click para não atrapalhar o uso.
    """
    try:
        img = tk.PhotoImage(data=BASE64_LOGO)
    except tk.TclError:
        # Base64 inválido ou Tk sem suporte a PNG
        return None, None

    # Usa o mesmo fundo do Text (evita 'unknown color name ""')
    try:
        bg = text_widget.cget("background")
        if not bg:
            # fallback: pega do container do Text
            bg = text_widget.master.cget("background")
    except Exception:
        bg = None  # se der algo errado, omitimos

    kwargs = dict(image=img, borderwidth=0, highlightthickness=0)
    if bg:
        kwargs["bg"] = bg

    lbl = tk.Label(text_widget, **kwargs)
    lbl.place(relx=0.5, rely=0.5, anchor="center")

    # Recentraliza ao redimensionar
    def _recenter(_evt=None):
        try:
            lbl.place_configure(relx=0.5, rely=0.5)
        except Exception:
            pass

    text_widget.bind("<Configure>", _recenter)

    # Repassar interações para o Text (para não bloquear)
    lbl.bind("<Button-1>", lambda e: (text_widget.focus_set(), "break"))
    # Scroll no Windows:
    lbl.bind("<MouseWheel>", lambda e: (text_widget.event_generate("<MouseWheel>", delta=e.delta), "break"))
    # Scroll no X11 (Linux):
    lbl.bind("<Button-4>", lambda e: (text_widget.event_generate("<Button-4>"), "break"))
    lbl.bind("<Button-5>", lambda e: (text_widget.event_generate("<Button-5>"), "break"))

    # Evita GC
    if not hasattr(text_widget, "_wm_refs"):
        text_widget._wm_refs = {}
    text_widget._wm_refs["img"] = img
    text_widget._wm_refs["label"] = lbl

    return img, lbl


# ===================== GUI - Aba DISCOVERY ICMP =====================

class DiscoveryICMPTab(Frame):
    def __init__(self, master):
        super().__init__(master)

        self.net_var = StringVar(value="138.117.28.0/22")
        self.workers_var = IntVar(value=DEFAULT_WORKERS_ICMP)

        top = Frame(self)
        top.pack(padx=8, pady=6, fill="x")

        Label(top, text="Rede (CIDR) ex: 10.0.0.0/22:").grid(row=0, column=0, sticky="w")
        Entry(top, textvariable=self.net_var, width=22).grid(row=0, column=1, sticky="w", padx=4)

        Label(top, text="/24 simultâneos:").grid(row=0, column=2, sticky="w", padx=(10, 0))
        Entry(top, textvariable=self.workers_var, width=6).grid(row=0, column=3, sticky="w", padx=4)

        self.start_btn = Button(top, text="Iniciar", command=self.start)
        self.start_btn.grid(row=0, column=4, padx=8)

        self.cancel_btn = Button(top, text="Cancelar", state="disabled", command=self.cancel)
        self.cancel_btn.grid(row=0, column=5)

        self.export_btn = Button(top, text="Exportar CSV", state="disabled", command=self.export_csv)
        self.export_btn.grid(row=0, column=6, padx=8)

        mid = Frame(self)
        mid.pack(padx=8, pady=(6, 3), fill="x")

        Label(mid, text="Progresso:").pack(side="left")
        self.progress = ttk.Progressbar(mid, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(side="left", padx=8, fill="x", expand=True)

        self.status_label = Label(mid, text="Pronto")
        self.status_label.pack(side="right")

        bottom = Frame(self)
        bottom.pack(padx=8, pady=6, fill="both", expand=True)

        self.result_box = scrolledtext.ScrolledText(bottom, wrap="none")
        self.result_box.pack(fill="both", expand=True)

        # >>> Marca d'água sobre a área de logs desta aba
        attach_watermark_to_text(self.result_box)

        # internals
        self._stop_event = threading.Event()
        self._queue = Queue()
        self._results = []
        self._executor = None
        self._total_subnets = 0
        self._done_subnets = 0

        self.after(200, self._process_queue)

    def _process_queue(self):
        try:
            while True:
                typ, data = self._queue.get_nowait()
                if typ == "log":
                    self.result_box.insert("end", data + "\n"); self.result_box.see("end")
                elif typ == "progress":
                    self._done_subnets = data; self._update_progress_ui()
                elif typ == "result":
                    self._results.append(data)
                    if data.get("cancelled"):
                        status = "CANCELADO"; found_ip = ""
                    else:
                        status = "FOUND" if data["found"] else "NONE"
                        found_ip = data["found_ip"] or ""
                    attempts = data.get("attempts", 0)
                    loss = (data.get("last_result") or {}).get("packet_loss") or ""
                    self.result_box.insert("end", f"{data['subnet']}\t{status}\t{found_ip}\ttries:{attempts}\tloss:{loss}\n")
                    self.result_box.see("end")
                elif typ == "done":
                    self._queue.put(("log", "Varredura concluída."))
                    self.start_btn.config(state="normal"); self.cancel_btn.config(state="disabled"); self.export_btn.config(state="normal")
        except Empty:
            pass
        self.after(200, self._process_queue)

    def _update_progress_ui(self):
        pct = int((self._done_subnets / self._total_subnets) * 100) if self._total_subnets else 0
        self.progress["value"] = pct
        self.status_label.config(text=f"{self._done_subnets}/{self._total_subnets} ({pct}%)")

    def start(self):
        net_text = self.net_var.get().strip()
        try:
            network = ipaddress.ip_network(net_text, strict=False)
        except Exception as e:
            messagebox.showerror("Erro", f"Rede inválida: {e}"); return

        if network.version != 4:
            messagebox.showerror("Erro", "Apenas IPv4 suportado nesta aba."); return

        if network.prefixlen <= 24:
            subnets = list(network.subnets(new_prefix=24))
        else:
            subnets = [network]

        self._total_subnets = len(subnets)
        if self._total_subnets == 0:
            messagebox.showinfo("Info", "Nenhum /24 para varrer."); return

        self._results.clear()
        self._done_subnets = 0
        self.progress["value"] = 0
        self.result_box.delete("1.0", "end")
        self.result_box.insert("end", f"Iniciando varredura em {self._total_subnets} sub-redes (/24)\n")
        self.result_box.see("end")
        self.start_btn.config(state="disabled"); self.cancel_btn.config(state="normal"); self.export_btn.config(state="disabled")
        self._stop_event.clear()

        max_workers = max(1, int(self.workers_var.get()))
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        threading.Thread(target=self._submit_subnets, args=(subnets,), daemon=True).start()

    def _submit_subnets(self, subnets):
        futures = {}
        try:
            for subnet in subnets:
                if self._stop_event.is_set():
                    self._queue.put(("log", "Cancelado antes de submeter todos os /24.")); break
                fut = self._executor.submit(scan_subnet_until_found, subnet, self._stop_event)
                futures[fut] = subnet

            for fut in as_completed(list(futures.keys())):
                if self._stop_event.is_set():
                    for f in futures: f.cancel()
                    self._queue.put(("log", "Cancelando execuções...")); break
                try:
                    res = fut.result()
                except Exception as e:
                    subnet = str(futures.get(fut, "unknown"))
                    res = {"subnet": subnet, "found": False, "found_ip": None, "attempts": 0,
                           "last_result": {"output": str(e)}, "cancelled": False}
                self._queue.put(("result", res))
                self._done_subnets += 1; self._queue.put(("progress", self._done_subnets))
        finally:
            if self._executor: self._executor.shutdown(wait=False)
            self._queue.put(("done", True))

    def cancel(self):
        self._stop_event.set()
        self.cancel_btn.config(state="disabled")
        self._queue.put(("log", "Pedido de cancelamento recebido. Aguardando tarefas ativas..."))

    def export_csv(self):
        if not self._results:
            messagebox.showinfo("Info", "Não há resultados para exportar."); return
        path = filedialog.asksaveasfilename(title="Salvar CSV", defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv")])
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["subnet", "found", "found_ip", "attempts", "packet_loss", "last_output"])
                for r in self._results:
                    last = r.get("last_result") or {}
                    packet_loss = last.get("packet_loss") or ""
                    output = (last.get("output") or "").strip().replace("\n", "\\n")
                    w.writerow([r.get("subnet"), r.get("found"), r.get("found_ip"), r.get("attempts"), packet_loss, output])
            messagebox.showinfo("Exportado", f"CSV salvo em: {path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar CSV: {e}")

# ===================== GUI - Aba TCP PING =====================

class TCPPingTab(Frame):
    def __init__(self, master):
        super().__init__(master)

        self.targets_var = StringVar(value="8.8.8.8")
        self.ports_var = StringVar(value="443")
        self.count_var = IntVar(value=DEFAULT_TCP_COUNT)
        self.interval_var = DoubleVar(value=DEFAULT_TCP_INTERVAL)
        self.timeout_var = DoubleVar(value=DEFAULT_TCP_TIMEOUT)
        self.workers_var = IntVar(value=DEFAULT_WORKERS_TCP)

        top = Frame(self); top.pack(padx=8, pady=6, fill="x")

        Label(top, text="Host:").grid(row=0, column=0, sticky="w")
        Entry(top, textvariable=self.targets_var, width=40).grid(row=0, column=1, sticky="w", padx=4, columnspan=3)

        Label(top, text="Porta:").grid(row=1, column=0, sticky="w")
        Entry(top, textvariable=self.ports_var, width=20).grid(row=1, column=1, sticky="w", padx=4)

        Label(top, text="Tentativas:").grid(row=1, column=2, sticky="e")
        Entry(top, textvariable=self.count_var, width=6).grid(row=1, column=3, sticky="w", padx=4)

        Label(top, text="Intervalo (s):").grid(row=2, column=0, sticky="w")
        Entry(top, textvariable=self.interval_var, width=8).grid(row=2, column=1, sticky="w", padx=4)

        Label(top, text="Timeout (s):").grid(row=2, column=2, sticky="e")
        Entry(top, textvariable=self.timeout_var, width=8).grid(row=2, column=3, sticky="w", padx=4)

        Label(top, text="Concorrência:").grid(row=2, column=4, sticky="e", padx=(10,0))
        Entry(top, textvariable=self.workers_var, width=8).grid(row=2, column=5, sticky="w", padx=4)

        self.start_btn = Button(top, text="Iniciar", command=self.start)
        self.start_btn.grid(row=0, column=4, padx=8)

        self.cancel_btn = Button(top, text="Cancelar", state="disabled", command=self.cancel)
        self.cancel_btn.grid(row=0, column=5)

        self.export_btn = Button(top, text="Exportar CSV", state="disabled", command=self.export_csv)
        self.export_btn.grid(row=0, column=6, padx=8)

        mid = Frame(self); mid.pack(padx=8, pady=(6,3), fill="x")
        Label(mid, text="Progresso:").pack(side="left")
        self.progress = ttk.Progressbar(mid, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(side="left", padx=8, fill="x", expand=True)
        self.status_label = Label(mid, text="Pronto"); self.status_label.pack(side="right")

        bottom = Frame(self); bottom.pack(padx=8, pady=6, fill="both", expand=True)
        self.result_box = scrolledtext.ScrolledText(bottom, wrap="none")
        self.result_box.pack(fill="both", expand=True)

        # >>> Marca d'água sobre a área de logs desta aba
        attach_watermark_to_text(self.result_box)

        # internals
        self._stop_event = threading.Event()
        self._queue = Queue()
        self._executor = None
        self._summaries = []      # summaries finais por host/porta
        self._attempts_log = []   # tentativas individuais (para CSV detalhado)
        self._total_targets = 0
        self._done_targets = 0

        self.after(200, self._process_queue)

    def _parse_list_ints(self, txt: str):
        out = []
        for p in txt.replace(";", ",").replace("|", ",").split(","):
            p = p.strip()
            if not p: continue
            try:
                out.append(int(p))
            except ValueError:
                pass
        return sorted(set(out))

    def _parse_hosts(self, txt: str):
        parts = []
        for token in txt.replace(",", " ").split():
            t = token.strip()
            if t:
                parts.append(t)
        # de-dup preservando ordem
        seen = set(); out = []
        for p in parts:
            if p not in seen:
                seen.add(p); out.append(p)
        return out

    def _process_queue(self):
        try:
            while True:
                typ, data = self._queue.get_nowait()
                if typ == "log":
                    self.result_box.insert("end", data + "\n"); self.result_box.see("end")
                elif typ == "progress":
                    self._done_targets = data; self._update_progress_ui()
                elif typ == "attempt":
                    self._attempts_log.append(data)
                    if data["ok"]:
                        self.result_box.insert("end", f"{data['host']}:{data['port']}  OK  {data['rtt_ms']:.2f} ms\n")
                    else:
                        self.result_box.insert("end", f"{data['host']}:{data['port']}  FAIL  {data.get('error')}\n")
                    self.result_box.see("end")
                elif typ == "summary":
                    self._summaries.append(data)
                    s = data
                    self.result_box.insert("end",
                        f"SUM {s['host']}:{s['port']}  sent:{s['sent']} recv:{s['recv']} "
                        f"loss:{s['loss_pct']}%  rtt(min/avg/max): {s['min_ms']} / {s['avg_ms']} / {s['max_ms']}\n")
                    self.result_box.see("end")
                elif typ == "done":
                    self._queue.put(("log", "TCP ping finalizado."))
                    self.start_btn.config(state="normal"); self.cancel_btn.config(state="disabled"); self.export_btn.config(state="normal")
        except Empty:
            pass
        self.after(200, self._process_queue)

    def _update_progress_ui(self):
        pct = int((self._done_targets / self._total_targets) * 100) if self._total_targets else 0
        self.progress["value"] = pct
        self.status_label.config(text=f"{self._done_targets}/{self._total_targets} ({pct}%)")

    def start(self):
        hosts = self._parse_hosts(self.targets_var.get())
        ports = self._parse_list_ints(self.ports_var.get())
        if not hosts:
            messagebox.showerror("Erro", "Informe ao menos um host."); return
        if not ports:
            messagebox.showerror("Erro", "Informe ao menos uma porta."); return

        count = max(1, int(self.count_var.get()))
        interval = max(0.0, float(self.interval_var.get()))
        timeout = max(0.1, float(self.timeout_var.get()))
        workers = max(1, int(self.workers_var.get()))

        # reset UI
        self._summaries.clear(); self._attempts_log.clear()
        self._done_targets = 0; self._total_targets = len(hosts) * len(ports)
        self.progress["value"] = 0
        self.result_box.delete("1.0", "end")
        if len(hosts) == 1 and len(ports) == 1:
            self.result_box.insert("end", f"Iniciando TCP ping em {hosts[0]}:{ports[0]}\n\n")
        else:
            self.result_box.insert("end", "Iniciando TCP ping em:\n")
            for h in hosts:
                for p in ports:
                    self.result_box.insert("end", f"  → {h}:{p}\n")
            self.result_box.insert("end", "\n")
        self.result_box.see("end")

        self.start_btn.config(state="disabled"); self.cancel_btn.config(state="normal"); self.export_btn.config(state="disabled")
        self._stop_event.clear()

        # dispare execuções
        self._executor = ThreadPoolExecutor(max_workers=workers)
        threading.Thread(target=self._submit_targets, args=(hosts, ports, count, interval, timeout), daemon=True).start()

    def _submit_targets(self, hosts, ports, count, interval, timeout):
        futures = {}
        try:
            for h in hosts:
                if self._stop_event.is_set():
                    break
                fut = self._executor.submit(
                    tcp_ping_target, h, ports, count, interval, timeout, self._queue, self._stop_event
                )
                futures[fut] = h

            # 'attempt' e 'summary' chegam em tempo real pela fila.
            # Aguardamos apenas para saber quando cada host terminou e atualizar progresso.
            for fut in as_completed(list(futures.keys())):
                if self._stop_event.is_set():
                    for f in futures: f.cancel()
                    self._queue.put(("log", "Cancelando execuções...")); break

                try:
                    _ = fut.result()  # sincroniza fim do host
                except Exception as e:
                    self._queue.put(("log", f"Erro em alvo {futures.get(fut)}: {e}"))

                # progresso: +N portas concluídas para este host
                self._done_targets += len(ports)
                self._queue.put(("progress", self._done_targets))
        finally:
            if self._executor: self._executor.shutdown(wait=False)
            self._queue.put(("done", True))

    def cancel(self):
        self._stop_event.set()
        self.cancel_btn.config(state="disabled")
        self._queue.put(("log", "Pedido de cancelamento recebido. Aguardando tarefas ativas..."))

    def export_csv(self):
        if not (self._summaries or self._attempts_log):
            messagebox.showinfo("Info", "Não há resultados para exportar."); return

        path = filedialog.asksaveasfilename(title="Salvar CSV (resumo)",
                                            defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv")])
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["host", "port", "sent", "recv", "loss_pct", "min_ms", "avg_ms", "max_ms", "last_error"])
                for s in self._summaries:
                    w.writerow([s["host"], s["port"], s["sent"], s["recv"], s["loss_pct"],
                                s["min_ms"], s["avg_ms"], s["max_ms"], s["last_error"]])
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar resumo: {e}")
            return

        # opcional: exportar tentativas detalhadas também
        if messagebox.askyesno("Exportar", "Deseja salvar também um CSV com as tentativas detalhadas?"):
            path2 = filedialog.asksaveasfilename(title="Salvar CSV (tentativas)",
                                                 defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv")])
            if path2:
                try:
                    with open(path2, "w", newline="", encoding="utf-8") as f2:
                        w2 = csv.writer(f2)
                        w2.writerow(["host", "port", "ok", "rtt_ms", "error"])
                        for a in self._attempts_log:
                            w2.writerow([a["host"], a["port"], a["ok"], a.get("rtt_ms"), a.get("error")])
                except Exception as e:
                    messagebox.showerror("Erro", f"Falha ao salvar tentativas: {e}")

# ===================== App principal com abas =====================

class NetToolsGUI:
    def __init__(self, root: Tk):
        root.title("IPRoute - Net Tools TCP PING & DISCOVERY ICMP")
        root.geometry("760x680")

        nb = ttk.Notebook(root)
        self.tab_tcp = TCPPingTab(nb)
        self.tab_icmp = DiscoveryICMPTab(nb)

        nb.add(self.tab_tcp, text="TCP PING")
        nb.add(self.tab_icmp, text="DISCOVERY ICMP")
        nb.pack(fill="both", expand=True)

def main():
    root = Tk()
    app = NetToolsGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
