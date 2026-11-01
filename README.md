# AntiV

Antivírus simples para Windows 10 feito em Python. Ele varre arquivos e pastas, olha os processos que estão rodando e tem um monitor em tempo real que avisa quando acontece alguma coisa estranha no computador.

É um projeto de estudo. Ele não substitui o Windows Defender, então deixe o Defender ligado e use o AntiV como uma segunda camada.

## O que ele faz

* varredura de arquivo, pasta ou disco inteiro (modo rápido, completo e profundo)
* compara o hash SHA-256 dos arquivos com uma lista de ameaças conhecidas
* procura padrões suspeitos dentro dos arquivos (as regras ficam em `data/rules.json`)
* analisa executáveis (packers, seções estranhas, entropia alta), scripts ofuscados e documentos do Office com macro
* olha dentro de arquivos ZIP sem extrair nada no disco
* quarentena: isola o arquivo suspeito e dá para restaurar depois
* monitor em tempo real: processos, rede, arquivos novos, ransomware e itens de inicialização
* interface gráfica (tkinter) e também funciona pelo terminal

## Como instalar

Precisa do Python 3.10 ou mais novo. Na instalação do Python, marque "Add Python to PATH" e deixe marcada a opção do tcl/tk, que é o que traz a interface gráfica.

```
pip install -r requirements.txt
```

## Como usar

Interface gráfica: dê dois cliques no `AntiV.pyw` (ou rode `python -m antiv`). Se der algum erro, o `Iniciar_AntiV.bat` mostra a mensagem no terminal.

Pelo terminal:

```
python -m antiv scan D:\
python -m antiv scan C:\pasta --mode fast
python -m antiv scan D:\ --workers 8 --quarantine
python -m antiv processes
python -m antiv monitor --test
python -m antiv quarantine list
python -m antiv quarantine restore --id ID_DO_ITEM
```

Para escanear o `C:\` inteiro, abra como Administrador, senão algumas pastas do sistema ficam com acesso negado.

### Modos de varredura

* rápida: só arquivos com extensão de risco (exe, dll, scripts, documentos do Office, zip e parecidos)
* completa: todos os arquivos, é o padrão
* profunda: todos os arquivos, sem limite de tamanho, e as regras olham o arquivo inteiro

Em SSD ele usa várias threads. Em HD usa poucas threads e lê em blocos grandes, porque ler muita coisa ao mesmo tempo deixa o HD mais lento. O tipo do disco é detectado sozinho, mas dá para escolher na mão. Arquivos que não mudaram desde a última varredura são pulados (cache).

## Monitor em tempo real

Fica na aba "Monitor em tempo real" ou no comando `python -m antiv monitor`. Ele não olha só o arquivo, olha o comportamento:

* processos: linha de comando, quem abriu quem (por exemplo Word abrindo PowerShell), programas rodando de pasta temporária e nomes imitando processos do Windows
* rede: programa que não deveria usar internet conectado nela e conexões em intervalos regulares
* arquivos: analisa arquivo novo em Downloads e Temp e detecta ransomware (muitos arquivos sendo reescritos ou renomeados rápido). Tem a opção de arquivos isca
* inicialização: itens novos em Run, pasta Inicializar, tarefas agendadas e serviços

Cada processo recebe uma pontuação: 40 ou mais é aviso, 70 ou mais é alto e 90 ou mais é crítico. Os alertas mostram o código MITRE ATT&CK da técnica. As regras ficam em `data/behavior_rules.json`.

Dá para suspender, encerrar ou isolar o programa pelos botões da aba. Nada acontece sozinho por padrão. Em alertas altos ele salva um dossiê em `incidents/` e a telemetria fica em `logs/telemetry.jsonl`. O botão "Testar monitor" inicia um processo inofensivo só para gerar um alerta de teste.

## Estrutura

```
antiv/            código do programa
  engine.py       varredura paralela
  analyzer.py     análise de cada arquivo
  heuristics.py   heurísticas (executáveis, scripts, Office)
  signatures.py   hashes e regras de padrões
  quarantine.py   quarentena
  gui.py          interface gráfica
  cli.py          comandos do terminal
  edr/            monitor em tempo real
data/             regras e lista de assinaturas
tests/            testes
```

## Testes

```
python -m unittest discover -s tests -v
```

Para ver uma detecção sem o Defender atrapalhar, vá na aba "Base de dados", clique em "Criar arquivo de teste inofensivo" e escaneie a pasta onde ele foi criado.

Para aumentar a base, use o botão "Importar lista de hashes" (um arquivo txt ou csv com hashes SHA-256).

## Limitações

* só detecta o que as regras e os hashes descrevem, a base é pequena
* o monitor roda em modo usuário (usa psutil), não tem driver de kernel, então processos que duram menos de uns 0,3 segundos podem passar
* não faz sandbox, não lê a memória dos processos e não confere assinatura digital
* RAR e 7z só são checados pelo hash do arquivo
* a quarentena usa XOR, que serve para impedir que o arquivo seja executado sem querer, mas não é criptografia de verdade
* pode dar falso positivo em coisa legítima, principalmente heurísticas e macros de empresa
* sem o pacote `watchdog` os arquivos são vigiados por varredura periódica, que é mais pesada
* o Defender pode reclamar dos arquivos `data/rules.json` e `data/behavior_rules.json`, porque eles têm texto de comandos suspeitos usados como regra. Se acontecer, adicione a pasta do projeto nas exclusões

## Aviso

Use por sua conta e risco, em computadores seus ou que você tem permissão para mexer. O projeto é para estudo.
