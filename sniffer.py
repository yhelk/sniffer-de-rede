"""Sniffer de rede educacional feito com Scapy.

USE SOMENTE EM REDES SUAS OU COM AUTORIZAÇÃO. Capturar tráfego de terceiros é
ilegal. Veja o aviso no README.
"""
import argparse
import csv
import socket
import sys
from datetime import datetime
from functools import lru_cache

from resumo import Resumo

CAMPOS_CSV = [
    "data_hora", "protocolo", "ip_origem", "porta_origem",
    "ip_destino", "porta_destino", "tamanho_bytes", "nome_destino",
]


def extrair_registro(pacote) -> dict | None:
    """Converte um pacote do Scapy em dicionário. Devolve None se não for IP."""
    from scapy.all import IP, TCP, UDP  # import tardio: só precisa do scapy aqui

    if not pacote.haslayer(IP):
        return None

    protocolo, porta_origem, porta_destino = "OUTRO", "", ""
    if pacote.haslayer(TCP):
        protocolo = "TCP"
        porta_origem, porta_destino = pacote[TCP].sport, pacote[TCP].dport
    elif pacote.haslayer(UDP):
        protocolo = "UDP"
        porta_origem, porta_destino = pacote[UDP].sport, pacote[UDP].dport

    return {
        "data_hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocolo": protocolo,
        "ip_origem": pacote[IP].src,
        "porta_origem": porta_origem,
        "ip_destino": pacote[IP].dst,
        "porta_destino": porta_destino,
        "tamanho": len(pacote),
    }


@lru_cache(maxsize=1024)
def nome_do_host(ip: str) -> str:
    """Consulta DNS reverso. O cache evita repetir a consulta para o mesmo IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "nao_identificado"


def ler_argumentos(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Sniffer de rede educacional (Scapy).")
    p.add_argument("-i", "--interface", help="interface de rede (padrão: a do Scapy)")
    p.add_argument("-c", "--count", type=int, default=20,
                   help="quantos pacotes capturar (0 = sem limite; Ctrl+C para parar)")
    p.add_argument("-f", "--filtro", default="",
                   help='filtro BPF, ex.: "tcp port 443"')
    p.add_argument("--csv", metavar="ARQUIVO",
                   help="salva os pacotes em CSV (o arquivo fica fora do Git)")
    p.add_argument("--resolver-nomes", action="store_true",
                   help="resolve o nome do destino via DNS reverso (mais lento)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = ler_argumentos(argv)
    try:
        from scapy.all import sniff, conf
    except ImportError:
        print("Instale as dependências: pip install -r requirements.txt")
        return 1

    resumo = Resumo()
    arquivo = writer = None
    if args.csv:
        arquivo = open(args.csv, "w", newline="", encoding="utf-8")
        writer = csv.DictWriter(arquivo, fieldnames=CAMPOS_CSV, extrasaction="ignore")
        writer.writeheader()

    def tratar(pacote):
        reg = extrair_registro(pacote)
        if reg is None:
            return
        reg["tamanho_bytes"] = reg["tamanho"]
        reg["nome_destino"] = (
            nome_do_host(reg["ip_destino"]) if args.resolver_nomes else ""
        )
        resumo.adicionar(reg)
        if writer:
            writer.writerow(reg)
        destino = reg["nome_destino"] or reg["ip_destino"]
        print(f"{reg['data_hora']} | {reg['protocolo']:<5} | "
              f"{reg['ip_origem']} -> {destino}:{reg['porta_destino']} "
              f"({reg['tamanho']} B)")

    print(f"[*] Interface: {args.interface or conf.iface} | filtro: {args.filtro or 'nenhum'}")
    try:
        sniff(iface=args.interface, filter=args.filtro or None,
              prn=tratar, count=args.count, store=False)
    except PermissionError:
        print("Sem permissão. Rode como administrador (Windows) ou com sudo (Linux).")
        return 1
    except KeyboardInterrupt:
        print("\n[!] Captura interrompida.")
    finally:
        if arquivo:
            arquivo.close()

    print("\n" + resumo.formatar())
    return 0


if __name__ == "__main__":
    sys.exit(main())
