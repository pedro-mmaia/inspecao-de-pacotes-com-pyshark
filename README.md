# 🛡️ Live Port Scan Detector com PyShark & BPF
### *Mini-NIDS (Network Intrusion Detection System) para Detecção de Varredura de Portas em Tempo Real*

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![PyShark](https://img.shields.io/badge/PyShark-0.6%2B-informational.svg)](https://github.com/KimiNewt/pyshark)
[![Wireshark/TShark](https://img.shields.io/badge/Engine-TShark%20%2F%20BPF-blueviolet.svg?logo=wireshark&logoColor=white)](https://tshark.dev/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1046%20(Discovery)-red.svg)](https://attack.mitre.org/techniques/T1046/)
[![Focus](https://img.shields.io/badge/Cybersecurity-Blue%20Team%20%2F%20SOC-green.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Sumário Executivo

O **Live Port Scan Detector** é um sensor defensivo de segurança de rede (*Network IDS*) de baixo overhead, projetado para monitorar tráfego ativamente e em tempo real em interfaces de rede locais (Wi-Fi ou Ethernet). 

Inspecionando os pacotes na velocidade do tráfego através de **filtros BPF (*Berkeley Packet Filter*) a nível de kernel**, o sensor identifica assinaturas preliminares de reconhecimento de adversários, com foco primário em **Port Scans (Varreduras de Portas)** como as realizadas pelo `nmap -sS` (*TCP SYN Stealth Scan*).

Este projeto foi construído sob a perspectiva de **Engenharia de Detecção e Operações de SOC (Security Operations Center)**, visando mitigar a fase de sondagem antes que os atacantes progridam para a exploração de vulnerabilidades.

---

## 🎯 Alinhamento com MITRE ATT&CK®

| Tática | Identificador | Técnica | Descrição no Contexto do Projeto |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | [TA0043](https://attack.mitre.org/tactics/TA0043/) | Active Scanning ([T1595](https://attack.mitre.org/techniques/T1595/)) | O invasor sonda blocos de IP e portas para mapear hosts e serviços disponíveis na rede. |
| **Discovery** | [TA0007](https://attack.mitre.org/tactics/TA0007/) | Network Service Discovery ([T1046](https://attack.mitre.org/techniques/T1046/)) | Tentativas deliberadas de enumerar portas e serviços ativos na máquina monitorada através de pacotes TCP SYN. |

---

## 🧠 Arquitetura e Engenharia de Detecção

O detector combina filtragem no espaço de kernel com processamento de estruturas de dados em memória no espaço de usuário:

```mermaid
flowchart TD
    A[Tráfego de Rede na Interface] --> B{BPF Filter no Kernel\n'tcp-syn e not tcp-ack'}
    B -- Descartado no Kernel --> X[Tráfego Normal:\nACK, FIN, SYN-ACK, Payload]
    B -- Encaminhado --> C[TShark Engine / PyShark\nLiveCapture]
    C --> D[Parser Python:\nExtração de ip.src e tcp.dstport]
    D --> E[Armazenamento em Memória\nregistro_conexoes[ip_origem].add]
    E --> F{Total de Portas Únicas >= 15?}
    F -- Não --> G[Continua Monitorando]
    F -- Sim --> H{IP Já Alertado?\nips_alertados}
    H -- Sim --> I[Throttling:\nSuprime Alerta Duplicado]
    H -- Não --> J[🚨 EMITE ALERTA DE PORT SCAN!\nRegistra em ips_alertados]
```

### 1. Filtragem de Baixo Nível no Kernel (BPF - Berkeley Packet Filter)
Para evitar que o pipeline em Python processe gigabytes de dados desnecessários, o detector aplica um filtro BPF nativo diretamente na captura do socket via TShark:

```text
tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0
```

* **Operação bit a bit:** Avalia os sinalizadores TCP. Garante que o bit `SYN` (0x02) esteja ativado enquanto o bit `ACK` (0x10) esteja estritamente desligado.
* **Benefício de SOC/Performance:** Apenas requisições de início de handshake (Passo 1 do *TCP 3-Way Handshake*) sobem para o user-space. Sessões já estabelecidas, transferências de arquivos e tráfego de dados volumoso são filtrados pelo kernel, mantendo o consumo de CPU e memória reduzidos.

### 2. Mapeamento em Memória e Distinção de Ataques
* **Extração L3/L4:** Os campos `pacote.ip.src` (IP de origem) e `pacote.tcp.dstport` (porta visada) são lidos sob demanda.
* **Uso Estratégico de `set()`:** As portas contatadas por um IP são armazenadas em um conjunto (`set`). Isso permite diferenciar com precisão cirúrgica:
  * **Port Scan (Varredura):** Um mesmo IP contatando portas **únicas e distintas** (ex: portas 21, 22, 80, 443, 3389).
  * **SYN Flood / DoS:** Um atacante inundando uma única porta específica (ex: 50.000 pacotes SYN contra a porta 80). Em um DoS, o `len(set)` continuará igual a 1, evitando falsos positivos de varredura.
* **Limiar Configurável (`LIMITE_DE_PORTAS = 15`):** Caso o atacante tente bater em 15 ou mais serviços distintos, o gatilho de alerta de intrusão é disparado.

### 3. Mecanismo Anti-Fadiga de Alertas (Throttling / Anti-Spam)
Em varreduras agressivas (ex: `nmap -p-` cobrindo 65.535 portas), um script ingênuo imprimiria dezenas de milhares de alertas. O detector utiliza o conjunto `ips_alertados = set()`:
* Quando o IP atinge o limiar, o alerta é emitido imediatamente.
* O IP é marcado em `ips_alertados`, garantindo que um mesmo invasor receba apenas **um alerta de incidente**, preservando a legibilidade do console do analista e a estabilidade do sistema.

### 4. Ciclo de Vida e Encerramento Gracioso (Signal Handling)
* Tratamento de interrupção manual via `KeyboardInterrupt` (`Ctrl + C`).
* Bloco `finally` encarregado de invocar `captura.close()`, liberando os descritores de arquivo, fechando os pipes do `tshark` e encerrando o processo sem travamentos de buffers assíncronos.

---

## 🛠️ Requisitos e Pré-requisitos

* **Sistema Operacional:** Linux (Ubuntu 20.04+, Debian 11+, Kali Linux, Fedora ou similares)
* **Python:** 3.12 ou superior
* **TShark:** Motor de análise de rede Wireshark CLI instalado e acessível no `$PATH`
* **Privilégios:** Permissão para capturar pacotes na interface de rede (`sudo` ou permissões via `setcap` / grupo `wireshark`)

---

## 🚀 Guia de Instalação e Execução

### Passo 1: Instalação das Dependências do Sistema

No terminal do Ubuntu/Debian, atualize os repositórios e instale o `tshark`, `git` e ferramentas do Python:

```bash
sudo apt update
sudo apt install -y tshark git python3 python3-venv
```

> [!NOTE]  
> Durante a instalação do `tshark`, o sistema perguntará se usuários sem privilégios de superusuário devem ter permissão para capturar pacotes (*"Should non-superusers be able to capture packets?"*). Escolha **`<Yes>`** se desejar capturar sem precisar rodar diretamente como `root`.

Selecione o seu usuário para o grupo do Wireshark (opcional, para execução não-root):
```bash
sudo usermod -aG wireshark $USER
newgrp wireshark
```

### Passo 2: Clonar o Repositório e Configurar o Ambiente Virtual

```bash
git clone https://github.com/pedro-mmaia/inspecao-de-pacotes-com-pyshark.git
cd inspecao-de-pacotes-com-pyshark

# Criar o ambiente virtual isolado
python3 -m venv venv

# Ativar o ambiente virtual
source venv/bin/activate

# Instalar os requisitos
pip install --upgrade pip
pip install -r requirements.txt
```

### Passo 3: Identificar a Interface de Rede Local

Antes de iniciar a captura, identifique o nome exato da interface de rede ativa na sua máquina:

```bash
ip -br link
```
*Exemplo de saída:*
```text
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
eth0             DOWN           08:00:27:11:22:33 <BROADCAST,MULTICAST> 
wlo1             UP             a4:c3:f0:44:55:66 <BROADCAST,MULTICAST,UP,LOWER_UP>
```

> [!IMPORTANT]  
> Abra o arquivo `detecao.py` e verifique se o parâmetro `interface` corresponde à sua interface ativa (ex: `wlo1`, `eth0`, `ens33` ou `enp3s0`).
> ```python
> captura = pyshark.LiveCapture(interface="wlo1", ...)
> ```

### Passo 4: Executar o Detector

Com o ambiente ativado, execute o script:

```bash
sudo $(which python3) detecao.py
```

---

## 🧪 Validação Prática em Laboratório (Simulando o Ataque)

Para validar a eficácia da detecção em um ambiente de testes, utilize uma máquina secundária na mesma rede (ou sua própria máquina direcionada ao IP local) e execute uma varredura com o **Nmap**:

### 1. Ataque TCP SYN Stealth Scan (Nmap)
```bash
# Varredura em 50 portas comuns no host monitorado
nmap -sS -p 1-50 <IP_DO_SENSOR>
```

### 2. Saída Esperada no Sensor (Terminal do SOC)
Quando o invasor ultrapassa a 15ª porta distinta visada, o detector dispara instantaneamente:

```text
ALERTA! Possível Port Scan detectado vindo do endereço IP 192.168.1.105

 Número de portas contatadas: 15
```

Se o atacante continuar a varredura até a porta 1.000, nenhum alerta adicional poluente será impresso devido à desduplicação do `ips_alertados`.

---

## 📂 Estrutura do Repositório

```text
inspecao-de-pacotes-com-pyshark/
│
├── .gitignore              # Ignora ambientes virtuais, dumps PCAP e caches
├── README.md               # Documentação técnica e operacional
├── requirements.txt        # Dependências do projeto (pyshark>=0.6)
└── detecao.py              # Código-fonte do detector de Port Scan
```

---

## 🔭 Roadmap e Melhorias de Engenharia Defensiva (Blue Team)

- [ ] **Alerta Multicanal (Webhook):** Encaminhamento automático de alertas formatados para Microsoft Teams, Slack ou Discord via Webhook.
- [ ] **Integração SIEM (Syslog / CEF):** Padronização de logs no padrão CEF (*Common Event Format*) ou ECS (*Elastic Common Schema*) para envio a Splunk / ELK / Wazuh.
- [ ] **Active Response (IPS):** Disparo de regra temporária no `iptables` ou `nftables` para bloquear o IP atacante em tempo real (*Drop/Reject*).
- [ ] **Janela Deslizante de Tempo (Time-Window Decay):** Implementação de expiração de IPs após um determinado intervalo (ex: `collections.deque` com timestamps) para evitar falsos positivos acumulados ao longo de dias.
- [ ] **CLI Parameters (`argparse`):** Parametrização da interface e do limiar via linha de comando (`--interface`, `--threshold`).

---

## ⚖️ Aviso Legal & Uso Ético

> [!WARNING]  
> Este software foi desenvolvido exclusivamente para propósitos educacionais, laboratoriais e de monitoramento de segurança defensiva em redes autorizadas. A execução de varreduras de portas ou interceptação de pacotes em redes sem consentimento prévio e formal é ilegal e viola legislações vigentes (como a Lei Geral de Proteção de Dados - LGPD e leis de crimes cibernéticos).