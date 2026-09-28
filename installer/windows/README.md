# Instalador Windows do NetGuard

Este pacote deixa o NetGuard instalavel por interface grafica, sem entregar uma lista de comandos CLI ao cliente.

## O que ele faz

- Checa se `docker` e `docker compose` estao disponiveis.
- Copia o pacote do NetGuard para `C:\ProgramData\NetGuard`.
- Cria o `.env` com valores padrao seguros para laboratorio/cliente.
- Executa `docker compose -p netguard up -d --build` por tras da interface.
- Permite iniciar, parar e abrir o NetGuard pela propria janela.

## Gerar EXE

No PowerShell:

```powershell
.\installer\windows\build-installer.ps1
```

O executavel sai em:

```text
installer\windows\dist\NetGuardInstaller.exe
```

## Observacoes comerciais

Para um instalador final de venda, o proximo passo e assinar o EXE, embutir icone/branding, validar privilegios administrativos e trocar senhas padrao no primeiro acesso. A base operacional ja esta pronta para esconder a complexidade do Docker do cliente.
