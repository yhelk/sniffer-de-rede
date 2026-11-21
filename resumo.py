"""Lógica de estatísticas do sniffer, sem dependência do scapy (fácil de testar)."""
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Resumo:
    """Acumula estatísticas de pacotes capturados."""

    total_pacotes: int = 0
    total_bytes: int = 0
    por_protocolo: Counter = field(default_factory=Counter)
    por_destino: Counter = field(default_factory=Counter)

    def adicionar(self, registro: dict) -> None:
        """Soma um registro (o dicionário devolvido por `extrair_registro`)."""
        self.total_pacotes += 1
        self.total_bytes += registro["tamanho"]
        self.por_protocolo[registro["protocolo"]] += 1
        self.por_destino[registro["ip_destino"]] += 1

    def top_destinos(self, n: int = 5) -> list[tuple[str, int]]:
        return self.por_destino.most_common(n)

    def formatar(self, n_destinos: int = 5) -> str:
        if self.total_pacotes == 0:
            return "Nenhum pacote IP capturado."
        linhas = [
            f"Pacotes: {self.total_pacotes} | Bytes: {self.total_bytes}",
            "Por protocolo: "
            + ", ".join(f"{p}={q}" for p, q in self.por_protocolo.most_common()),
            "Principais destinos:",
        ]
        linhas += [f"  {ip}: {q} pacote(s)" for ip, q in self.top_destinos(n_destinos)]
        return "\n".join(linhas)
