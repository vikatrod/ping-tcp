import socket
import time
import threading
import queue
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

class TcpPingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IPRoute - TCP Ping - Monitor")
        self.running = False
        self.log_queue = queue.Queue()

        # ====== Form ======
        frm = ttk.Frame(root, padding=10)
        frm.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        self.host_var = tk.StringVar(value="")
        self.port_var = tk.StringVar(value="")
        self.timeout_var = tk.StringVar(value="2")
        self.interval_var = tk.StringVar(value="1")
        self.total_var = tk.StringVar(value="10")

        row = 0
        ttk.Label(frm, text="Host / IP:").grid(row=row, column=0, sticky="e")
        ttk.Entry(frm, textvariable=self.host_var, width=38).grid(row=row, column=1, columnspan=3, sticky="we", padx=5)
        row += 1

        ttk.Label(frm, text="Porta:").grid(row=row, column=0, sticky="e")
        ttk.Entry(frm, textvariable=self.port_var, width=8).grid(row=row, column=1, sticky="w", padx=5)

        ttk.Label(frm, text="Timeout (s):").grid(row=row, column=2, sticky="e")
        ttk.Entry(frm, textvariable=self.timeout_var, width=8).grid(row=row, column=3, sticky="w", padx=5)
        row += 1

        ttk.Label(frm, text="Intervalo (s):").grid(row=row, column=0, sticky="e")
        ttk.Entry(frm, textvariable=self.interval_var, width=8).grid(row=row, column=1, sticky="w", padx=5)

        ttk.Label(frm, text="Tentativas:").grid(row=row, column=2, sticky="e")
        ttk.Entry(frm, textvariable=self.total_var, width=8).grid(row=row, column=3, sticky="w", padx=5)
        row += 1

        # Botões
        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=row, column=0, columnspan=4, pady=(6, 0), sticky="we")
        self.start_btn = ttk.Button(btn_frame, text="Iniciar", command=self.start_test)
        self.stop_btn = ttk.Button(btn_frame, text="Parar", command=self.stop_test, state="disabled")
        self.export_btn = ttk.Button(btn_frame, text="Exportar CSV", command=self.export_csv, state="disabled")
        self.clear_btn = ttk.Button(btn_frame, text="Limpar", command=self.clear_log)

        self.start_btn.pack(side="left")
        self.stop_btn.pack(side="left", padx=6)
        self.export_btn.pack(side="left")
        self.clear_btn.pack(side="left", padx=6)
        row += 1

        # ====== Log ======
        log_frame = ttk.Frame(root, padding=(10, 6, 10, 10))
        log_frame.grid(row=1, column=0, sticky="nsew")
        root.rowconfigure(1, weight=1)

        self.text = tk.Text(log_frame, height=16, wrap="none")
        self.text.configure(state="disabled")
        yscroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        # ====== Estatísticas ======
        stats_frame = ttk.Frame(root, padding=(10, 0, 10, 10))
        stats_frame.grid(row=2, column=0, sticky="we")
        for i in range(6):
            stats_frame.columnconfigure(i, weight=1)

        self.sent = 0
        self.ok = 0
        self.fail = 0
        self.rtts = []

        self.lbl_sent = ttk.Label(stats_frame, text="Enviados: 0")
        self.lbl_recv = ttk.Label(stats_frame, text="Recebidos: 0")
        self.lbl_loss = ttk.Label(stats_frame, text="Perda: 0.0%")
        self.lbl_min = ttk.Label(stats_frame, text="Min: -")
        self.lbl_avg = ttk.Label(stats_frame, text="Méd: -")
        self.lbl_max = ttk.Label(stats_frame, text="Máx: -")

        self.lbl_sent.grid(row=0, column=0, sticky="w")
        self.lbl_recv.grid(row=0, column=1, sticky="w")
        self.lbl_loss.grid(row=0, column=2, sticky="w")
        self.lbl_min.grid(row=0, column=3, sticky="e")
        self.lbl_avg.grid(row=0, column=4, sticky="e")
        self.lbl_max.grid(row=0, column=5, sticky="e")

        # Atualizador do log
        self.root.after(100, self.drain_log_queue)

    # ---------- Utilidades GUI ----------
    def log(self, msg):
        self.log_queue.put(msg)
    
    def clear_log(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self.reset_stats()

    def drain_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.text.configure(state="normal")
                self.text.insert("end", msg + "\n")
                self.text.see("end")
                self.text.configure(state="disabled")
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.drain_log_queue)

    def reset_stats(self):
        self.sent = 0
        self.ok = 0
        self.fail = 0
        self.rtts = []
        self.update_stats_labels()

    def update_stats_labels(self):
        loss = (self.fail / self.sent * 100) if self.sent else 0.0
        self.lbl_sent.config(text=f"Enviados: {self.sent}")
        self.lbl_recv.config(text=f"Recebidos: {self.ok}")
        self.lbl_loss.config(text=f"Perda: {loss:.1f}%")
        if self.rtts:
            self.lbl_min.config(text=f"Min: {min(self.rtts):.2f} ms")
            self.lbl_avg.config(text=f"Méd: {sum(self.rtts)/len(self.rtts):.2f} ms")
            self.lbl_max.config(text=f"Máx: {max(self.rtts):.2f} ms")
        else:
            self.lbl_min.config(text="Min: -")
            self.lbl_avg.config(text="Méd: -")
            self.lbl_max.config(text="Máx: -")

    # ---------- Execução ----------
    def start_test(self):
        try:
            host = self.host_var.get().strip()
            port = int(self.port_var.get())
            timeout = float(self.timeout_var.get())
            interval = float(self.interval_var.get())
            total = int(self.total_var.get())
            if not host or port <= 0 or total <= 0 or timeout <= 0 or interval < 0:
                raise ValueError
        except Exception:
            messagebox.showerror("Erro", "Verifique os campos: host, porta, timeout, intervalo e tentativas.")
            return

        # Resolve DNS antes (opcional)
        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror as e:
            messagebox.showerror("Erro", f"Falha ao resolver '{host}': {e}")
            return

        self.reset_stats()
        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.export_btn.config(state="disabled")
        self.log(f"Testando TCP ping em {host} ({resolved}):{port} ({total} tentativas)")

        args = (host, port, timeout, interval, total)
        t = threading.Thread(target=self.worker, args=args, daemon=True)
        t.start()

    def stop_test(self):
        self.running = False

    def worker(self, host, port, timeout, interval, total):
        for i in range(1, total + 1):
            if not self.running:
                break
            self.sent += 1
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                inicio = time.time()
                s.connect((host, port))
                fim = time.time()
                s.close()
                rtt = (fim - inicio) * 1000.0
                self.rtts.append(rtt)
                self.ok += 1
                self.log(f"#{i} Resposta em {rtt:.2f} ms")
            except socket.timeout:
                self.fail += 1
                self.log(f"#{i} Timeout após {timeout}s")
            except socket.error as e:
                self.fail += 1
                self.log(f"#{i} Falha: {e}")
            self.update_stats_labels()
            # Respeita intervalo, mas permite parar rápido
            if interval > 0:
                for _ in range(int(interval * 10)):
                    if not self.running:
                        break
                    time.sleep(0.1)

        self.running = False
        self.update_stats_labels()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self.sent > 0:
            self.export_btn.config(state="normal")
        self.log("\n--- Estatísticas TCP ---")
        loss = (self.fail / self.sent * 100) if self.sent else 0.0
        self.log(f"Enviados: {self.sent}, Recebidos: {self.ok}, Perdidos: {self.fail} ({loss:.1f}% perda)")
        if self.rtts:
            self.log(f"Tempo mínimo: {min(self.rtts):.2f} ms")
            self.log(f"Tempo máximo: {max(self.rtts):.2f} ms")
            self.log(f"Tempo médio: {sum(self.rtts)/len(self.rtts):.2f} ms")

    def export_csv(self):
        if not self.sent:
            return
        path = filedialog.asksaveasfilename(
            title="Salvar resultados",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")]
        )
        if not path:
            return

        # Exporta log detalhado (linha a linha) + estatísticas
        try:
            # Reconstrói linhas do Text
            content = self.text.get("1.0", "end").strip().splitlines()
            rows = []
            for line in content:
                rows.append([line])

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["Log"])
                writer.writerows(rows)
            messagebox.showinfo("Exportado", f"Arquivo salvo em:\n{path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    # Estilo básico
    try:
        from tkinter import ttk
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    app = TcpPingGUI(root)
    root.minsize(640, 480)
    root.mainloop()
