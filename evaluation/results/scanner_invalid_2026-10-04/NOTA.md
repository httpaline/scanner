# Execuções inválidas do harness (04/10/2026)

Essas três execuções do `run_scanner.py` NÃO são válidas para a avaliação.

**Causa:** um servidor uvicorn iniciado manualmente ainda ocupava a porta 8000. O harness
tentou subir a API, falhou silenciosamente (stderr descartado) e a verificação de
prontidão consultou o servidor antigo. As três execuções rodaram contra a mesma instância,
sem reset entre elas.

**Evidência:** a run1 começou com o estado limpo (BOLA lê `Usuario A`). As run2 e run3
herdaram a escalada de privilégio que o módulo API3 fez na run1 (BOLA lê
`Mass Assignment Test`).

**Valor metodológico:** a checagem de reprodutibilidade detectou a contaminação de estado.
Isso comprova empiricamente a necessidade do reset entre execuções exigido pela Seção 4.4.2
do TCC1.

**Correção aplicada:** o harness agora checa a porta antes de subir, grava o log do uvicorn
em `api.log` e falha na hora se o processo morrer durante a subida.
