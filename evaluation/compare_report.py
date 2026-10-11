"""
Gera a tabela/relatório comparativo final entre o scanner proposto e o ZAP, a
partir das métricas calculadas por metrics.py — o resultado central do Capítulo 5
(Resultados Esperados / Comparação com o ZAP) do TCC2.

Ver docs/decisions.md, seção 7, para as regras de comparação usadas no metrics.py.

Arquivo de partida para o Luiz. A função abaixo tem a assinatura e a descrição do
que deve fazer; o corpo precisa ser implementado.
"""
from metrics import compute_metrics, load_elapsed_seconds, load_ground_truth, load_scanner_findings, load_zap_alerts
from metrics import SCANNER_METADATA_PATH, ZAP_METADATA_PATH


def build_comparison_table(scanner_metrics: dict, zap_metrics: dict) -> str:
  """
  Monta a tabela final (sugestão: Markdown, fácil de colar no TCC2) comparando
  scanner x ZAP lado a lado: VP, FP, FN, Taxa de Detecção, tempo de execução.

  Lembrar de citar, junto da tabela ou em nota, as limitações já documentadas na
  seção 7 do docs/decisions.md: a assimetria de identidades (scanner usa 2, ZAP usa
  1) e a assimetria de tempo (login conta pro scanner, não conta pro ZAP; volume de
  requisições bem diferente entre as duas ferramentas).
  """
  raise NotImplementedError


def main() -> None:
  ground_truth = load_ground_truth()

  scanner_metrics = compute_metrics(
    "scanner", load_scanner_findings(), ground_truth, load_elapsed_seconds(SCANNER_METADATA_PATH)
  )
  zap_metrics = compute_metrics(
    "zap", load_zap_alerts(), ground_truth, load_elapsed_seconds(ZAP_METADATA_PATH)
  )

  print(build_comparison_table(scanner_metrics, zap_metrics))


if __name__ == "__main__":
  main()
