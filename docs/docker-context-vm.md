# Docker Context SSH para a VM NetGuard

Ambiente oficial de validacao: VM Linux `192.168.56.15`.

O Codex no Windows deve executar Docker/Compose sempre contra o Docker Engine da VM usando o contexto `netguard-vm`:

```powershell
docker --context netguard-vm compose -p netguard config --quiet
docker --context netguard-vm compose -p netguard ps
docker --context netguard-vm compose -p netguard up -d --build
docker --context netguard-vm compose -p netguard ps -a
```

Nao use `docker compose ...` sem `--context netguard-vm` para validacao oficial, pois isso usa o Docker Desktop local do Windows.

## Estado verificado em 2026-04-27

- Contexto Docker `netguard-vm`: existe e aponta para `ssh://netguard@192.168.56.15`.
- Comando executado: `docker context update netguard-vm --docker "host=ssh://netguard@192.168.56.15"`.
- Contexto ativo do Docker CLI alterado para `netguard-vm` com `docker context use netguard-vm`.
- Arquivo SSH local criado em `C:\Users\Rodig\.ssh\config` com alias `netguard-vm`, `IdentityFile ~/.ssh/id_ed25519` e permissao ajustada para o usuario atual.
- SSH nao interativo ainda bloqueado: `ssh netguard@192.168.56.15` retornou `Permission denied (publickey,password)`.
- `docker --context netguard-vm ps` e `docker --context netguard-vm info` nao conseguiram concluir porque o Docker CLI aguardou autenticacao SSH.
- `docker --context netguard-vm compose -p netguard config --quiet`: OK, pois valida apenas a configuracao local do Compose e nao precisa consultar o engine remoto.
- Endpoints atuais da VM responderam:
  - `http://192.168.56.15:8000/health`: API respondeu, HEAD retorna 405 porque o endpoint aceita GET.
  - `http://192.168.56.15:3000`: Grafana respondeu HTTP 200.
  - `http://192.168.56.15:8081/monitoring/alerts`: web respondeu HTTP 200, indicando que a VM ainda esta com a versao HTTP antiga.
  - `https://192.168.56.15:8081/monitoring/alerts`: falhou com erro TLS, porque o rebuild HTTPS ainda nao foi aplicado no Docker Engine da VM.

## Passo necessario na VM

O Windows ja possui chave publica em `C:\Users\Rodig\.ssh\id_ed25519.pub`.

Autorize essa chave no usuario `netguard` da VM. Na VM, execute como o usuario `netguard`:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAUWIDME8cgHtVcAOsE7lo5kUbcc5ef/GowwEn7Ohqfn' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Depois valide:

```powershell
ssh netguard@192.168.56.15 "whoami; groups; docker ps"
docker --context netguard-vm info
docker --context netguard-vm ps
```

Se `docker ps` na VM pedir `sudo` ou negar permissao, adicione o usuario ao grupo `docker`:

```bash
sudo usermod -aG docker $USER
```

Em seguida encerre a sessao SSH e entre novamente. Sem renovar a sessao, a nova associacao ao grupo pode nao surtir efeito.

## Validacao oficial apos liberar SSH

Execute a partir do Windows, no workspace `\\192.168.56.15\netguard`:

```powershell
docker --context netguard-vm compose -p netguard config --quiet
docker --context netguard-vm compose -p netguard up -d --build
docker --context netguard-vm compose -p netguard ps -a
```

Endpoints esperados depois do rebuild remoto:

```powershell
curl.exe http://192.168.56.15:8000/health
curl.exe http://192.168.56.15:8000/health/deep
curl.exe -k https://192.168.56.15:8081/monitoring/alerts
curl.exe -k https://192.168.56.15:8081/api/health
curl.exe http://192.168.56.15:3000
```

Observacao: a web atual do projeto foi ajustada para HTTPS. Por isso, depois que o Compose remoto for aplicado, a validacao correta da UI deve usar `https://192.168.56.15:8081`, nao `http://192.168.56.15:8081`.

## Comandos de comparacao

Use estes comandos para evitar confusao entre Docker Desktop local e VM:

```powershell
docker context show
docker ps
docker --context netguard-vm ps
```

O criterio de sucesso e `docker --context netguard-vm ps` mostrar os containers reais do NetGuard na VM.
