# Projeto VPN com Criptografia Multi-Algoritmo e Gestão Avançada

Sistema VPN educacional implementado em Python que demonstra comunicação segura entre clientes UDP através de um túnel TCP criptografado, com gestão avançada de utilizadores, monitorização TCP e sistema híbrido de armazenamento.

## Funcionalidades Implementadas

### F5 - Criptografia Simétrica Avançada ✅
- **Dois algoritmos simétricos**: César Generalizada e Vigenère Generalizada
- **Deslocamento dinâmico**: Cada mensagem usa nonce único (number used once)
- **Conjunto completo de caracteres**: Suporte a 95 caracteres ASCII imprimíveis (32-126)
- **Troca segura de chaves**: Diffie-Hellman para estabelecimento de chaves simétricas
- **Verificação de integridade**: Hash SHA-256 de cada mensagem
- **Autenticação**: HMAC-SHA256 para verificação de autenticidade

### F6 - Gestão Multi-Algoritmo ✅
- **Alternância dinâmica**: Mudança de algoritmo durante execução
- **Configuração em tempo real**: Activar/desactivar HMAC dinamicamente
- **Compatibilidade**: Suporte completo para ambos os algoritmos
- **Negociação automática**: Cliente e servidor negoceiam algoritmo preferido
- **Estado persistente**: Configurações mantidas durante a sessão

### F7 - Monitor TCP Completo ✅
- **Parâmetros TCP detalhados**: Window size, buffer sizes, keep-alive, TCP nodelay
- **Métricas de performance**: Throughput, latência, taxa de sucesso
- **Estatísticas em tempo real**: Contadores de bytes, mensagens, erros
- **Relatórios formatados**: Exportação para ficheiros com timestamps
- **Comparação entre componentes**: Client vs Server com análise automática

### Sistema de Gestão Híbrido ✅
- **Gestão de utilizadores**: Autenticação, criação, remoção de utilizadores
- **Armazenamento híbrido**: Servidor VPN (remoto) + fallback local
- **Sessões seguras**: Tokens de sessão com timeout automático
- **Roles de utilizador**: Administradores e utilizadores normais
- **Relatórios administrativos**: Guardar relatórios TCP no servidor ou localmente

## Arquitectura do Sistema

```
┌─────────────┐    UDP     ┌─────────────┐    TCP (criptografado)    ┌─────────────┐    UDP     ┌─────────────┐
│  ProgUDP1   │ ────────▶ │ VPN Client  │ ──────────────────────────▶ │ VPN Server  │ ────────▶ │  ProgUDP2   │
│ (Porta 5001)│           │(Porta 6001) │                           │(Porta 6002) │           │(Porta 5002) │
└─────────────┘           └─────────────┘                           └─────────────┘           └─────────────┘
                                 │                                           │
                                 │ UDP (comandos)                  UDP (comandos) │
                                 ▼                                           ▼
                          ┌──────────────────────────────────────────────────────┐
                          │              Gestor VPN Principal                     │
                          │          (Porta 6003 - Respostas)                   │
                          │                                                      │
                          │  • Gestão de utilizadores híbrida                   │
                          │  • Monitor TCP (F7)                                 │
                          │  • Configuração multi-algoritmo (F6)               │
                          │  • Relatórios e estatísticas                       │
                          └──────────────────────────────────────────────────────┘
```

## Fluxo de Dados Detalhado

### 1. Estabelecimento da Conexão
```
VPN Client ←→ VPN Server (TCP porta 7001)
    │
    ├─ Diffie-Hellman Key Exchange
    ├─ Negociação de algoritmo (César/Vigenère)
    ├─ Configuração HMAC
    └─ Estabelecimento de chaves derivadas
```

### 2. Envio de Mensagem Criptografada
```
Gestor/ProgUDP1 → VPN Client → [CRIPTOGRAFIA] → VPN Server → ProgUDP2
                      │                              │
                      ├─ Nonce único gerado          ├─ Verificação HMAC
                      ├─ Cifra com algoritmo ativo   ├─ Verificação integridade
                      ├─ Hash SHA-256 calculado      ├─ Decifra com nonce
                      └─ HMAC-SHA256 calculado       └─ Encaminha mensagem limpa
```

### 3. Monitor TCP em Ação
```
Gestor → [MONITOR]comando → VPN Client/Server → Análise TCP → Resposta formatada
    │                            │                     │
    ├─ Solicita relatório       ├─ Coleta parâmetros   ├─ Estatísticas em tempo real
    ├─ Solicita estatísticas    ├─ Mede latência       ├─ Relatório detalhado
    └─ Compara componentes      └─ Calcula throughput  └─ Exporta para ficheiro
```

## Instalação e Execução

### Pré-requisitos
- Python 3.7+
- Módulos incluídos: `socket`, `threading`, `hashlib`, `secrets`, `json`

### Execução Automática (Recomendado)
```bash
# Inicia todo o sistema automaticamente
python gestor_vpn.py
```

O gestor irá:
1. Iniciar VPN Server, VPN Client e ProgUDP1 automaticamente
2. Aguardar login do utilizador (admin/admin123 por defeito)
3. Disponibilizar interface completa baseada no role do utilizador

### Execução Manual (Para Debug)

**Terminal 1 - VPN Server:**
```bash
python VPNServer.py
```

**Terminal 2 - VPN Client:**
```bash
python VPNClient.py
```

**Terminal 3 - ProgUDP1:**
```bash
python ProgUDP1.py
```

**Terminal 4 - ProgUDP2:**
```bash
python ProgUDP2.py
```

**Terminal 5 - Gestor Principal:**
```bash
python gestor_vpn.py
```

## Utilizadores Padrão

### Administrador
- **Username**: `admin`
- **Password**: `admin123`
- **Permissões**: Acesso completo a todas as funcionalidades

### Criar Novos Utilizadores
No menu de administrador: `Gerir utilizadores` → `Criar utilizador`

## Funcionalidades por Role

### Utilizadores Normais
- ✅ Enviar mensagens através do túnel VPN
- ✅ Ver estado do sistema
- ✅ Logout

### Administradores
- ✅ Todas as funcionalidades de utilizador normal
- ✅ **Gerir utilizadores**: Criar, listar, remover utilizadores
- ✅ **Controlar componentes**: Iniciar/parar sistema completo
- ✅ **Configurações de criptografia (F6)**:
  - Alterar algoritmo (César ↔ Vigenère)
  - Configurar HMAC (activar/desactivar)
  - Ver estado detalhado da criptografia
  - Testar criptografia em tempo real
- ✅ **Consultar parâmetros TCP (F7)**:
  - Relatórios completos (Client/Server)
  - Estatísticas básicas em tempo real
  - Comparação detalhada Client vs Server
  - Exportação automática para ficheiros

## Demonstração da Criptografia

### Exemplo de Deslocamento Dinâmico
```
Mensagem: "Olá mundo"
Envio 1: Nonce 1234567 → Cifra "X8#k9(nd*"
Envio 2: Nonce 8901234 → Cifra "P2&s7+nh%"
Envio 3: Nonce 5678901 → Cifra "M5!r4-ko@"
```

**Resultado**: A mesma mensagem produz cifras diferentes a cada envio!

### Debug da Criptografia
O ficheiro `debug_cripto.txt` regista em tempo real:
- Nonces gerados para cada mensagem
- Chaves dinâmicas derivadas
- Processo de cifragem e decifragem
- Verificações de integridade e autenticação

### Exemplo de Registo de Debug
```
[22:18:08] VPN CLIENT: Recebida mensagem UDP: 'Projeto de Criptografia Aplicada' - Texto claro: False
[22:18:08] Cifrando com VIGENERE: 'Projeto de Criptografia Aplicada'
[22:18:08] VIGENERE: Nonce gerado: 4292133250
[22:18:08] VIGENERE: Chave dinâmica: 'JsR}M"jUa...' para texto: Projeto de Criptografia Aplicada
[22:18:08] VPN CLIENT: Mensagem criptografada com VIGENERE: 'zfBh3vZUFm%c:$)kr@qes~h"t}G20]75' nonce: 4292133250
[22:18:08] VPN SERVER: Mensagem criptografada recebida com VIGENERE: 'zfBh3vZUFm%c:$)kr@qes~h"t}G20]75' nonce: 4292133250
[22:18:08] VPN SERVER: Mensagem decifrada: 'Projeto de Criptografia Aplicada'
```

## Portas e Comunicação

| Componente | Porta | Protocolo | Função |
|------------|-------|-----------|---------|
| ProgUDP1 | 5001 | UDP | Cliente UDP origem |
| ProgUDP2 | 5002 | UDP | Cliente UDP destino |
| VPN Client | 6001 | UDP | Recebe mensagens/comandos |
| VPN Server | 6002 | UDP | Recebe mensagens/comandos |
| VPN Client ↔ Server | 7001 | TCP | Túnel criptografado |
| Gestor (Respostas) | 6003 | UDP | Recebe respostas dos monitores |

## Exemplos de Uso

### 1. Enviar Mensagem Criptografada
```
Menu Administrador → Enviar mensagem → Criptografada
Mensagem: "Dados sensíveis"
Resultado: Mensagem cifrada com nonce único, verificada por HMAC
```

### 2. Alterar Algoritmo de Criptografia (F6)
```
Menu Administrador → Configurações de criptografia → Alterar algoritmo
Escolha: César → Vigenère
Resultado: Próximas mensagens usarão Vigenère com chaves dinâmicas
```

### 3. Consultar Parâmetros TCP (F7)
```
Menu Administrador → Consultar parâmetros TCP → Relatório completo - VPN Client
Resultado: Relatório detalhado com métricas de performance e parâmetros TCP
```

### 4. Comparar Performance TCP
```
Menu Administrador → Consultar parâmetros TCP → Comparar Client vs Server
Resultado: Análise comparativa com recomendações de performance
```

## Sistema de Gestão Híbrido

### Modo Remoto (Preferencial)
- Utilizadores armazenados no VPN Server
- Relatórios guardados no servidor
- Sessões geridas centralmente
- Comunicação via comandos UDP

### Modo Local (Fallback)
- Utilizadores em ficheiro local (`utilizadores.txt`)
- Relatórios guardados localmente
- Funciona quando servidor indisponível
- Interface idêntica ao modo remoto

### Transição Automática
O sistema tenta sempre o modo remoto primeiro e recorre ao local automaticamente se necessário.

## Ficheiros de Dados

### Utilizadores
- `vpn_utilizadores.txt`: Utilizadores no servidor (modo remoto)
- `utilizadores.txt`: Utilizadores locais (modo fallback)

### Relatórios TCP
- `vpn_relatorios/`: Pasta no servidor (modo remoto)
- `relatorio_local_*.txt`: Relatórios locais (modo fallback)
- `stats_tcp_*.txt`: Estatísticas TCP
- `comparacao_tcp_*.txt`: Comparações entre componentes

### Debug
- `debug_cripto.txt`: Registo detalhado da criptografia em tempo real

## Características de Segurança

### Confidencialidade ✅
- Algoritmos simétricos: César e Vigenère generalizadas
- Chaves únicas por sessão via Diffie-Hellman
- Deslocamento dinâmico com nonces únicos
- Suporte a 95 caracteres ASCII imprimíveis

### Integridade ✅
- Hash SHA-256 de cada mensagem
- Verificação automática na receção
- Detecção de mensagens corrompidas
- Registos de falhas de integridade

### Autenticação ✅
- HMAC-SHA256 para autenticação de mensagens
- Troca segura de chaves Diffie-Hellman
- Sistema de utilizadores com sessões
- Verificação de autenticidade automática

### Auditoria ✅
- Monitor TCP com estatísticas completas
- Registos detalhados de criptografia
- Relatórios exportáveis com timestamps
- Rastreamento completo de mensagens

## Tratamento de Erros

### Criptografia
- Verificação obrigatória de integridade e autenticação
- Fallback para mensagens em texto simples (para depuração)
- Registos detalhados de falhas criptográficas
- Regeneração automática de nonces

### Rede
- Reconexão automática configurável
- Timeouts configuráveis para todas as operações
- Detecção de ligações perdidas
- Gestão adequada de excepções de socket

### Sistema
- Fallback automático para modo local
- Limpeza adequada de recursos
- Handlers para sinais do sistema (SIGTERM)
- Registos de erro com timestamps

## Performance e Monitorização

### Monitor TCP (F7) - Métricas Coletadas
- **Tráfego**: Bytes enviados/recebidos por segundo
- **Latência**: Medição RTT em tempo real
- **Taxa de sucesso**: Percentagem de mensagens bem-sucedidas
- **Parâmetros TCP**: Window size, buffer sizes, keep-alive, nodelay
- **Throughput**: Cálculo automático baseado em histórico de 60 segundos

### Exemplo de Relatório TCP
```
============================================================
PARÂMETROS TCP - VPN CLIENT
============================================================
INFORMAÇÕES DA CONEXÃO:
  Estado: Conectado
  Endereço local: localhost:56088
  Endereço remoto: localhost:7001
  Tempo ativo: 02:26
  Conexão atual: 02:26

ESTATÍSTICAS DE TRÁFEGO:
  Bytes enviados: 106 B
  Bytes recebidos: 445 B
  Mensagens enviadas: 1
  Mensagens recebidas: 2
  Taxa de sucesso: 100.0%

MÉTRICAS DE PERFORMANCE:
  Throughput envio: 0.7 B/s
  Throughput recepção: 3.0 B/s
  Latência média: 2.3 ms

PARÂMETROS TCP:
  Window Size: 64.0 KB
  Buffer envio: 64.0 KB
  Buffer recepção: 64.0 KB
  Keep Alive: Inativo
  TCP No Delay: Inativo
============================================================
```

## Limitações e Considerações

### Educacionais
- Cifras de César e Vigenère são criptograficamente fracas
- Primo Diffie-Hellman relativamente pequeno (2^31-1)
- Destinado para fins educacionais, não produção

### Escalabilidade
- Um cliente VPN por servidor
- Utilizadores e sessões limitados
- Sem persistência entre reinicializações

### Funcionalidades Futuras Possíveis
- Suporte para múltiplos clientes simultâneos
- Algoritmos criptográficos mais robustos (AES)
- Interface gráfica web
- Persistência de dados
- Clustering de servidores

## Conclusão

Este projeto implementa com sucesso todas as funcionalidades exigidas (F5, F6, F7) e vai além com:

- **Sistema híbrido de gestão** com fallback automático
- **Monitor TCP completo** com exportação de relatórios
- **Criptografia multi-algoritmo** com deslocamento dinâmico
- **Interface de gestão avançada** baseada em roles
- **Auditoria completa** com registos detalhados

O sistema demonstra conceitos avançados de programação de redes, criptografia, gestão de sistemas e monitorização, servindo como excelente exemplo educacional de implementação VPN simplificada.

---

**Desenvolvido em Python para fins educacionais - Projeto VPN 2024/2025**