# Emissor de credenciais da sala de áudio e vídeo (Cloudflare Workers)

Com este pequeno servidor, só membros **aprovados** do portal entram na sala de áudio e vídeo das
sessões, com o nome verificado, e quem preside a sessão (e o administrador) entra como **moderador**.
Sem ele, a sala já funciona, mas qualquer pessoa que souber o endereço da sala pode entrar.

O plano gratuito do Cloudflare Workers basta (100 mil pedidos por dia).

## 1. Gerar a chave no JaaS

1. No painel do JaaS (jaas.8x8.vc), abra **API Keys → Add API Key → Generate API key pair**.
2. O navegador baixa um arquivo com a **chave privada**. Guarde-o: ele é secreto.
3. Anote o **Key ID** completo (formato `vpaas-magic-cookie-.../abc123`).

## 2. Criar o servidor no Cloudflare

1. Crie a conta gratuita em dash.cloudflare.com e confirme o e-mail.
2. No menu, abra **Workers & Pages → Create → Create Worker**.
3. Dê o nome `estraro-jaas` e clique em **Deploy** (ele cria um exemplo).
4. Clique em **Edit code**, apague todo o conteúdo, cole o conteúdo do arquivo `worker.js` desta pasta
   e clique em **Deploy**.
5. Anote o endereço do servidor (algo como `https://estraro-jaas.SEU-USUARIO.workers.dev`).

## 3. Configurar as variáveis

Em **Settings → Variables and Secrets**, adicione:

| Nome | Tipo | Valor |
|---|---|---|
| `JAAS_APP_ID` | Text | `vpaas-magic-cookie-1127c80e5f8f4ff294278b5ecbb32cac` |
| `JAAS_KEY_ID` | Text | o Key ID completo do passo 1 |
| `JAAS_PRIVATE_KEY` | **Secret** | todo o conteúdo do arquivo da chave privada, inclusive as linhas `-----BEGIN PRIVATE KEY-----` e `-----END PRIVATE KEY-----` |
| `FIREBASE_PROJECT_ID` | Text | `bel-estraro` |
| `ADMIN_EMAILS` | Text | `querino.neto@gmail.com` |
| `ALLOWED_ORIGINS` | Text | o endereço do portal, sem barra no final (ex.: `https://querinoneto.github.io`) |

Clique em **Deploy** para aplicar.

**Nunca** cole a chave privada em conversas, e-mails ou no repositório. Ela fica só no Cloudflare, como *Secret*.

## 4. Ligar no portal

Envie ao responsável pelo portal o endereço do servidor (passo 2.5). Ele vai em `index.html`, em
`CONFIG.jaas.tokenUrl`. Esse endereço não é secreto.

## Como o servidor decide

1. Confere o login no Firebase (assinatura do token do Google, projeto certo, validade e e-mail confirmado).
2. Lê, **com a credencial da própria pessoa**, o diretório `people` e a sessão no Firestore. As regras do
   Firestore só permitem essa leitura a quem tem acesso aprovado.
3. Exige que a sessão esteja **ao vivo**.
4. Assina a credencial do JaaS, válida por 4 horas, com o nome e o cargo da pessoa. É moderador quem
   preside ou convocou a sessão e quem está em `ADMIN_EMAILS`.
