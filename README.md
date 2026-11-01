# AntiV 0.3 — antivírus leve + EDR comportamental para Windows 10

Python 3.10+ • interface gráfica (tkinter) + linha de comando • dependências: `psutil` e `watchdog`.

## Instalação
1. Instale o Python em python.org (marque **Add Python to PATH** e deixe marcada a opção **tcl/tk and IDLE**, que traz a interface gráfica).
2. Na pasta do projeto: `pip install -r requirements.txt`

## Como abrir
- **Interface gráfica:** dê duplo clique em `AntiV.pyw` (ou `Iniciar_AntiV.bat`, que mostra erros se houver), ou rode `python -m antiv`.
- **Linha de comando:** veja abaixo.

Para verificar `C:\` inteiro, use o botão **Reabrir como Administrador** (barra inferior).

## Como a detecção funciona (vários métodos em uma única leitura do arquivo)
| Método | O que pega |
|---|---|
| Hash SHA-256 | Arquivos idênticos aos da base (`data/signatures.json` e listas em `data/hashes/`) |
| Padrões de bytes | Regras em `data/rules.json` (EICAR, PowerShell codificado, download+execução, apagar backups, autorun.inf, atalhos maliciosos…) filtradas pelo tipo do arquivo |
| Heurística de executáveis | Packers (UPX etc.), seção gravável+executável, entropia alta, ponto de entrada estranho, sem importações, muitas APIs de injeção |
| Heurística de scripts | Base64 gigante, ofuscação com Chr()/fromCharCode |
| Documentos Office | Macros VBA, executável embutido, modelo/objeto remoto |
| Disfarces | Dupla extensão (`fatura.pdf.exe`), caractere RLO, `.jpg` que é executável |
| Dentro de ZIP | Conteúdo analisado em memória, inclusive ZIP dentro de ZIP |

Níveis: **ALTA** = certeza (hash ou assinatura) • **Suspeito** = heurística, pode ser falso positivo • **Info** = observação (ex.: documento com macros).
Só detecções **ALTA** são isoladas automaticamente (se você marcar a opção). Suspeitos ficam para você revisar.

## Velocidade
- **SSD:** muitas threads em paralelo. **HDD:** 2 threads e blocos de 4 MB (leitura sequencial). O tipo é detectado sozinho (ou escolha manualmente).
- **Cache:** arquivos limpos que não mudaram são pulados nas próximas varreduras. O cache se invalida sozinho quando a base ou as regras mudam.
- **Modos:** Rápida (só extensões de risco) • Completa (tudo, padrão) • Profunda (tudo, sem limite de tamanho, regras no arquivo inteiro).
- Arquivos "somente na nuvem" (OneDrive) são pulados para não disparar downloads.


## Monitor em tempo real (EDR leve) — novo na 0.3
Aba **Monitor em tempo real** (ou `python -m antiv monitor`). Em vez de olhar só o arquivo, observa o **comportamento**:

| Camada | O que observa | Exemplos |
|---|---|---|
| Processos | Cada processo novo: linha de comando, cadeia pai→filho, local de origem, disfarces, análise estática do .exe, DLLs carregadas de pasta temporária | Word abrindo PowerShell com `-enc`; `vssadmin delete shadows`; `svchost.exe` fora do Windows; certutil/mshta/regsvr32 baixando código |
| Rede | Conexões de cada processo | Bloco de notas conectado à internet; conexões em intervalos regulares (beaconing de C2); varredura de muitos destinos |
| Arquivos | Pastas de documentos/downloads/temp | Arquivo novo analisado ao ser baixado; **ransomware** (muitos arquivos cifrados/renomeados em segundos, bilhete de resgate em várias pastas); **arquivos-isca** opcionais |
| Persistência | Run/RunOnce, Winlogon, IFEO, AppInit, pasta Inicializar, tarefas agendadas, serviços | Novo item de inicialização apontando para Temp ou para PowerShell codificado |

- **Pontuação por processo:** cada regra soma pontos (uma vez); 40+ = aviso, 70+ = alto, 90+ = crítico. Cada detecção traz o **ID MITRE ATT&CK** (ex.: T1059.001, T1490, T1486).
- **Resposta:** suspender (reversível), retomar, encerrar, encerrar + isolar o executável, ignorar programa (lista de confiáveis por caminho). **Nada é automático por padrão.** As opções automáticas são: suspender processos CRÍTICOS e isolar arquivos novos de certeza (ALTA). Processos essenciais do Windows e o próprio AntiV nunca são tocados.
- **Dossiê do incidente:** em alertas altos/críticos, salva em `incidents/` um JSON com árvore de processos, linha de comando, conexões, arquivos abertos, módulos e SHA-256.
- **Telemetria:** `logs/telemetry.jsonl` (com rotação) e aba de linha do tempo com filtro.
- **Teste seguro:** botão *Testar monitor* (ou `python -m antiv monitor --test`) inicia um processo inofensivo que dispara um alerta.
- As regras ficam em `data/behavior_rules.json` (regex + pontos + técnica ATT&CK) e podem ser editadas.

### Limites do monitor (leia)
- É de **modo usuário** (amostragem com psutil), sem driver de kernel nem ETW: processos que vivem menos de ~0,3 s podem passar; não vê injeção em memória nem lê a memória dos processos; quem tem privilégio de Administrador pode encerrar o AntiV. EDRs comerciais usam drivers de kernel.
- Sem Administrador, a linha de comando de processos de outros usuários/sistema não fica visível.
- Sem o pacote `watchdog`, arquivos são vigiados por varredura periódica (mais pesada e mais lenta).
- Ransomware: a atribuição ao processo responsável é uma estimativa (por volume de gravação). A suspensão automática só ocorre com isca tocada ou responsável claramente dominante.
- Pode gerar alertas em usos legítimos (macros de empresa, scripts de instalação que baixam e executam). Use *Ignorar programa*.

## Linha de comando
    python -m antiv scan D:\ --mode full
    python -m antiv scan D:\ --mode fast --disk ssd
    python -m antiv scan D:\ --workers 8 --quarantine
    python -m antiv scan C:\pasta --mode deep --no-cache
    python -m antiv processes
    python -m antiv monitor [--canaries] [--auto-suspend] [--folder PASTA] [--test] [--duration 60]
    python -m antiv quarantine list | restore --id <ID> | delete --id <ID>

`Ctrl+C` cancela e **salva o relatório parcial**.

## Testar com segurança
- **Sem risco de o Defender interferir:** aba *Base de dados* → *Criar arquivo de teste inofensivo…* → volte em *Varredura* e inicie. Deve aparecer uma detecção ALTA.
- **Testes automáticos:** `python -m unittest discover -s tests -v`
- O EICAR também é detectado (regra em hexadecimal), mas o Defender pode apagá-lo antes.

## Aumentar a base
Aba *Base de dados* → *Importar lista de hashes…* (arquivo .txt/.csv com SHA-256, um por linha; formatos de feeds públicos funcionam). Você também pode editar `data/rules.json` para adicionar regras.

## Limitações (seja realista)
- Não substitui o Windows Defender nem um EDR comercial.
- Sem emulação/sandbox e sem verificação da assinatura digital.
- ZIP/Office são analisados; RAR/7z só por hash do arquivo.
- Quarentena usa XOR (ofusca e impede execução), não criptografia forte.
- Heurísticas geram falsos positivos (ex.: instaladores legítimos empacotados).
- Se o Defender reclamar de `data/rules.json` (ele contém texto de comandos suspeitos usados como padrões), adicione a pasta do projeto às exclusões.
