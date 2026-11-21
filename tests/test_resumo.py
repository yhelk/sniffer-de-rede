import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from resumo import Resumo  # noqa: E402


def reg(proto="TCP", destino="1.1.1.1", tamanho=100):
    return {"protocolo": proto, "ip_destino": destino, "tamanho": tamanho}


class TestResumo(unittest.TestCase):
    def test_vazio(self):
        self.assertEqual(Resumo().formatar(), "Nenhum pacote IP capturado.")

    def test_totais(self):
        r = Resumo()
        r.adicionar(reg(tamanho=60))
        r.adicionar(reg("UDP", "8.8.8.8", 40))
        self.assertEqual(r.total_pacotes, 2)
        self.assertEqual(r.total_bytes, 100)
        self.assertEqual(r.por_protocolo["TCP"], 1)
        self.assertEqual(r.por_protocolo["UDP"], 1)

    def test_top_destinos_ordenado(self):
        r = Resumo()
        for _ in range(3):
            r.adicionar(reg(destino="9.9.9.9"))
        r.adicionar(reg(destino="1.1.1.1"))
        self.assertEqual(r.top_destinos(1), [("9.9.9.9", 3)])

    def test_formatar_contem_destinos(self):
        r = Resumo()
        r.adicionar(reg(destino="9.9.9.9"))
        texto = r.formatar()
        self.assertIn("9.9.9.9", texto)
        self.assertIn("TCP=1", texto)


if __name__ == "__main__":
    unittest.main()
