# Sniffer de Rede (Python + Scapy)

Projeto de estudos que captura pacotes de rede, mostra cada conexão em tempo real, resume o tráfego no final e, se você quiser, salva tudo em CSV. Feito para aprender como o tráfego IP, TCP e UDP funciona na prática.

> **Aviso ético e legal:** use apenas na sua própria rede ou com autorização por escrito. Capturar tráfego de terceiros é crime. Este código é educacional.

## O que ele faz
- Captura pacotes IP e identifica protocolo (TCP, UDP ou outro), IPs e portas.
- Aceita **filtro BPF** (ex.: `tcp port 443`), escolha de **interface** e **limite de pacotes**.
- Mostra um **resumo** ao final: total de pacotes e bytes, divisão por protocolo e os destinos mais frequentes.
- Opcional: resolve o nome do destino por DNS reverso (com cache) e exporta para **CSV**.

## Como usar
Requisitos: Python 3.10+ e, no Windows, o [Npcap](https://npcap.com/). No Linux/macOS, rode com `sudo`.

```bash
pip install -r requirements.txt

# captura 20 pacotes (padrão) e mostra o resumo
python sniffer.py

# só HTTPS, 50 pacotes, salvando em CSV e resolvendo nomes
python sniffer.py -c 50 -f "tcp port 443" --csv captura.csv --resolver-nomes
```

Exemplo de saída (ilustrativo):

```
2026-02-21 13:25:15 | TCP   | 192.168.0.10 -> 203.0.113.5:443 (55 B)
...
Pacotes: 20 | Bytes: 1480
Por protocolo: TCP=17, UDP=3
Principais destinos:
  203.0.113.5: 12 pacote(s)
```

## Estrutura
| Arquivo | Função |
|---|---|
| `sniffer.py` | Captura (Scapy), argumentos de linha de comando e CSV |
| `resumo.py` | Estatísticas dos pacotes, sem dependência do Scapy |
| `tests/test_resumo.py` | Testes automáticos da lógica de resumo |

Rodar os testes: `python -m unittest discover -s tests`

## Privacidade
Capturas contêm IPs e nomes de máquinas. Por isso `*.csv`, `*.pcap` e `*.pcapng` estão no `.gitignore` e **nunca devem ser publicados**.

## Próximos passos
- Detectar varredura de portas (muitos destinos em pouco tempo).
- Exportar também em `.pcap`.
- Gráfico simples de tráfego por protocolo.

## Aprendizados
Este projeto nasceu como um script de 20 linhas. Na evolução aprendi a separar a lógica do acesso à rede (para testar), usar argumentos de linha de comando e cuidar de dados sensíveis no Git.
