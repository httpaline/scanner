# Execuções do ZAP sem autenticação efetiva (04/10/2026)

Essas três execuções do `run_zap.py` NÃO são válidas para a comparação formal, que exige
o ZAP autenticado como `usuario_a`.

**Causa:** o valor do Replacer foi passado sem aspas (`replacement=Bearer <token>`). O
espaço pode ter separado o valor, e o ZAP enviou apenas `Bearer`. Nenhuma requisição
protegida recebeu `200` (os únicos `200` foram o login e a spec OpenAPI), e as respostas
de `/users/*` foram `401`, não os `404` observados no spike autenticado.

**O que os dados ainda mostram (sem autenticação):** o ZAP reproduziu seis tipos de alerta
iguais nas três execuções, exceto um alerta de sessão que variou de 2 para 1 na run3.
Detectou o stack trace do `/debug/crash` (API8) e a credencial na URL do `/auth/login`
(API2). Não detectou BOLA, BOPLA nem BFLA, o que era esperado sem autenticação, e por isso
esses três achados não informam nada sobre o ZAP autenticado.

**Correção aplicada:** o valor do Replacer agora vai entre aspas simples, como no spike, e
o harness faz uma requisição autenticada a `/users/1` antes de rodar o ZAP. Se a requisição
não retornar `200`, o harness para com erro.
