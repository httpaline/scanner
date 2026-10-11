"""
Calcula VP, FP, FN, Taxa de Detecção e tempo de execução, comparando os relatórios
do scanner e do ZAP contra o ground_truth.json.

Ver docs/decisions.md, seção 7, para todas as regras de comparação: identidade usada
pelo ZAP, corte de risco, regra de correspondência de endpoint, definição de tempo,
e qual execução usar (as 3 execuções de cada ferramenta são reproduzíveis entre si;
use uma só, ex. run1, para o cálculo — não tire média).

Arquivo de partida para o Luiz. As funções abaixo têm a assinatura e a descrição do
que fazem; os corpos precisam ser implementados.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH_PATH = ROOT / "vulnerable_api" / "ground_truth.json"
SCANNER_REPORT_PATH = ROOT / "evaluation" / "results" / "scanner" / "run1" / "report.json"
ZAP_REPORT_PATH = ROOT / "evaluation" / "results" / "zap" / "run1" / "report.json"
SCANNER_METADATA_PATH = ROOT / "evaluation" / "results" / "scanner" / "run1" / "metadata.json"
ZAP_METADATA_PATH = ROOT / "evaluation" / "results" / "zap" / "run1" / "metadata.json"

MIN_RISK = "Low"  # seção 7.2 do docs/decisions.md: corte de risco pros alertas do ZAP


def load_ground_truth() -> list[dict]:
  """Carrega vulnerable_api/ground_truth.json e devolve a lista de vulnerabilidades."""
  raise NotImplementedError


def load_scanner_findings() -> list[dict]:
  """Carrega o relatório do scanner (run1) e devolve a lista de achados (findings)."""
  raise NotImplementedError


def load_zap_alerts(min_risk: str = MIN_RISK) -> list[dict]:
  """
  Carrega o relatório do ZAP (run1) e devolve só os alertas que atingem o corte de
  risco (seção 7.2): Low ou acima — descarta os Informational. Alertas sobre o mesmo
  endpoint contam como um achado só, não um por alerta (mesma regra de agrupamento
  do scanner/report/generator.py).
  """
  raise NotImplementedError


def endpoint_matches(template: str, concrete: str) -> bool:
  """
  Compara um caminho-molde do ground_truth (ex. "/users/{id}") com um caminho
  concreto reportado pelo ZAP (ex. "/users/10"), segmento por segmento — qualquer
  segmento "{algo}" do molde aceita qualquer valor correspondente (seção 7.3).
  """
  raise NotImplementedError


def match_findings_to_ground_truth(findings: list[dict], ground_truth: list[dict]) -> dict:
  """
  Casa cada achado (do scanner ou do ZAP, já no formato comum categoria/método/caminho)
  com uma entrada do ground_truth, usando endpoint_matches + método HTTP + categoria.

  Devolve um dicionário com, por exemplo:
    {"matched": [...achados que bateram com alguma entrada...],
     "unmatched": [...achados sem correspondência no gabarito, ou seja, FP...]}
  """
  raise NotImplementedError


def load_elapsed_seconds(metadata_path: Path) -> float:
  """Lê metadata.json de uma execução (run_scanner.py/run_zap.py) e devolve elapsed_seconds."""
  raise NotImplementedError


def compute_metrics(tool_name: str, findings: list[dict], ground_truth: list[dict], elapsed_seconds: float) -> dict:
  """
  Calcula, para uma ferramenta:
    - VP: entradas do ground_truth com pelo menos um achado correspondente.
    - FP: achados sem correspondência no ground_truth (match_findings_to_ground_truth -> "unmatched").
    - FN: entradas do ground_truth sem nenhum achado correspondente.
    - TD (Taxa de Detecção): VP / (VP + FN) — Equação 4.1 do TCC1.
    - tempo de execução: elapsed_seconds.

  Devolve um dicionário com essas cinco informações.
  """
  raise NotImplementedError


def main() -> None:
  ground_truth = load_ground_truth()

  scanner_metrics = compute_metrics(
    "scanner",
    load_scanner_findings(),
    ground_truth,
    load_elapsed_seconds(SCANNER_METADATA_PATH),
  )
  zap_metrics = compute_metrics(
    "zap",
    load_zap_alerts(),
    ground_truth,
    load_elapsed_seconds(ZAP_METADATA_PATH),
  )

  print(json.dumps({"scanner": scanner_metrics, "zap": zap_metrics}, indent=2))


if __name__ == "__main__":
  main()
