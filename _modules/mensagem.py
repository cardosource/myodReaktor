import sys
from time import sleep
from abc import ABC, abstractmethod

class MensagemStrategy(ABC):
    @abstractmethod
    def mostrar_progresso(self, label: str, duration: float = 1.0, steps: int = 10):
        pass

class ProgressoVertical(MensagemStrategy):
    """Animação vertical com colunas coloridas e porcentagem"""

    def __init__(self):
        self.etapas = []

    def mostrar_progresso(self, label: str, duration: float = 1.0, steps: int = 10):
        self.etapas.append((label, duration, steps))
        if len(self.etapas) == 3:
            self._animar_colunas()

    def _animar_colunas(self):
        altura = max(steps for _, _, steps in self.etapas)
        colunas = len(self.etapas)
        largura_coluna = 17
        espacamento_topo = 10

        # Cores ANSI
        cores = ['\033[91m', '\033[93m', '\033[92m']
        RESET = '\033[0m'

        # Preenche o topo com espaço
        print("\n\n\n" * espacamento_topo)

        progresso = [['     ' for _ in range(colunas)] for _ in range(altura)]

        for col_index, (label, duration, steps) in enumerate(self.etapas):
            delay = duration / steps
            for filled in range(steps):
                for row in range(altura):
                    if row >= altura - filled - 1:
                        progresso[row][col_index] = cores[col_index] + '   ---------------     ' + RESET
                self._desenhar_frame(progresso, self.etapas, largura_coluna, altura, espacamento_topo, filled + 1, steps)
                sleep(delay)

        print("::: ============================================================ :::\n")
    def _desenhar_frame(self, progresso, etapas, largura_coluna, altura, espacamento_topo, filled, steps):
        sys.stdout.write(f"\033[{altura + 3 + espacamento_topo}F")
        sys.stdout.flush()

        for i, linha in enumerate(progresso):
           
            linha_formatada = ''
            for bloco in linha:
                linha_formatada += bloco.ljust(largura_coluna)
            if i >= altura - filled:
                porcentagem = int((i - (altura - filled) + 1) / steps * 100)
                #linha_formatada += f"[   {str(porcentagem).rjust(3)}% ]"
                #linha_formatada += f"[   {str(porcentagem).rjust(3)}% ]"
            print(linha_formatada.rstrip())

        nomes = [etapa[0].center(largura_coluna) for etapa in etapas]
        print(" | ".join(nomes))
        print()
