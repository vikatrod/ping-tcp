import argparse
import socket
import time
from contextlib import closing

def main():
    parser = argparse.ArgumentParser(
        description="TCP ping (teste de conexão TCP e medição de RTT)."
    )
    parser.add_argument("host", help="IP ou hostname")
    parser.add_argument("port", type=int, help="Porta TCP")
    parser.add_argument("-n", "--count", type=int, default=10,
                        help="Quantidade de tentativas (padrão: 10)")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Intervalo entre tentativas em segundos (padrão: 1.0)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="Timeout em segundos por tentativa (padrão: 2.0)")
    args = parser.parse_args()

    host = args.host
    port = args.port
    total_testes = max(1, args.count)
    interval = max(0.0, args.interval)
    timeout = max(0.001, args.timeout)

    # Resolve para exibir IP (não aborta se falhar)
    try:
        resolved_ip = socket.gethostbyname(host)
        alvo = f"{host} ({resolved_ip})"
    except socket.gaierror:
        alvo = host

    sucesso = 0
    falhas = 0
    tempos = []

    print(f"Testando TCP ping em {alvo}:{port} ({total_testes} tentativas)")
    try:
        for i in range(1, total_testes + 1):
            try:
                inicio = time.time()
                with closing(socket.create_connection((host, port), timeout=timeout)):
                    pass
                fim = time.time()
                rtt_ms = (fim - inicio) * 1000.0
                tempos.append(rtt_ms)
                sucesso += 1
                print(f"#{i} Resposta em {rtt_ms:.2f} ms")
            except socket.timeout:
                falhas += 1
                print(f"#{i} Timeout após {timeout}s")
            except OSError as e:
                falhas += 1
                print(f"#{i} Falha: {e}")

            if i != total_testes:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário (Ctrl+C). Exibindo estatísticas parciais...")

    # Estatísticas
    enviados = sucesso + falhas
    perda_pct = (falhas / enviados * 100.0) if enviados else 0.0
    print("\n--- Estatísticas TCP ---")
    print(f"Enviados: {enviados}, Recebidos: {sucesso}, Perdidos: {falhas} ({perda_pct:.1f}% perda)")
    if tempos:
        print(f"Tempo mínimo: {min(tempos):.2f} ms")
        print(f"Tempo máximo: {max(tempos):.2f} ms")
        print(f"Tempo médio: {sum(tempos)/len(tempos):.2f} ms")

if __name__ == "__main__":
    main()
