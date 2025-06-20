#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPNServer_corrigido.py - Servidor VPN corrigido com gestão administrativa
"""

import socket
import threading
import json
import time
import sys
import signal
import os
import hashlib
from datetime import datetime
from criptografia import GestorCriptografia
from monitor_tcp import MonitorTCP

class GestorUtilizadoresServidor:
    """Gestão de utilizadores no servidor"""
    
    def __init__(self):
        self.pasta_utilizadores = "vpn_utilizadores"
        self.ficheiro_utilizadores = os.path.join(self.pasta_utilizadores, "utilizadores.txt")
        self.utilizadores = {}
        self.sessoes_ativas = {}
        
        os.makedirs(self.pasta_utilizadores, exist_ok=True)
        self.carregar_utilizadores()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def carregar_utilizadores(self):
        try:
            if os.path.exists(self.ficheiro_utilizadores):
                with open(self.ficheiro_utilizadores, 'r', encoding='utf-8') as f:
                    for linha in f:
                        linha = linha.strip()
                        if linha and not linha.startswith('#'):
                            partes = linha.split('|')
                            if len(partes) == 4:
                                username, password_hash, role, data_criacao = partes
                                self.utilizadores[username] = {
                                    'password_hash': password_hash,
                                    'role': role,
                                    'data_criacao': data_criacao
                                }
            else:
                self.criar_utilizador("admin", "admin123", "administrador")
        except Exception as e:
            print(f"Erro ao carregar utilizadores: {e}")
    
    def guardar_utilizadores(self):
        try:
            with open(self.ficheiro_utilizadores, 'w', encoding='utf-8') as f:
                f.write("# Utilizadores VPN Server\n")
                f.write("# username|password_hash|role|data_criacao\n\n")
                
                for username, dados in self.utilizadores.items():
                    linha = f"{username}|{dados['password_hash']}|{dados['role']}|{dados['data_criacao']}\n"
                    f.write(linha)
        except Exception as e:
            print(f"Erro ao guardar utilizadores: {e}")
    
    def autenticar(self, username, password):
        if username in self.utilizadores:
            password_hash = self.hash_password(password)
            if self.utilizadores[username]['password_hash'] == password_hash:
                token_sessao = self.criar_sessao(username)
                return {
                    'username': username,
                    'role': self.utilizadores[username]['role'],
                    'data_criacao': self.utilizadores[username]['data_criacao'],
                    'token_sessao': token_sessao
                }
        return None
    
    def criar_sessao(self, username):
        token = hashlib.sha256(f"{username}:{time.time()}".encode()).hexdigest()[:16]
        self.sessoes_ativas[token] = {
            'username': username,
            'criada_em': time.time(),
            'ultimo_acesso': time.time()
        }
        return token
    
    def validar_sessao(self, token):
        if token in self.sessoes_ativas:
            sessao = self.sessoes_ativas[token]
            if time.time() - sessao['ultimo_acesso'] < 1800:
                sessao['ultimo_acesso'] = time.time()
                return sessao
            else:
                del self.sessoes_ativas[token]
        return None
    
    def criar_utilizador(self, username, password, role):
        if username in self.utilizadores:
            return False
        
        if role not in ['utilizador', 'administrador']:
            return False
        
        self.utilizadores[username] = {
            'password_hash': self.hash_password(password),
            'role': role,
            'data_criacao': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.guardar_utilizadores()
        return True

class GestorRelatoriosServidor:
    """Gestão de relatórios no servidor"""
    
    def __init__(self):
        self.pasta_relatorios = "vpn_relatorios"
        os.makedirs(self.pasta_relatorios, exist_ok=True)
    
    def guardar_relatorio_tcp(self, componente, relatorio, utilizador):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome_ficheiro = f"relatorio_tcp_{componente}_{timestamp}.txt"
            caminho_completo = os.path.join(self.pasta_relatorios, nome_ficheiro)
            
            with open(caminho_completo, 'w', encoding='utf-8') as f:
                f.write("RELATÓRIO TCP (VPN SERVER)\n")
                f.write("="*50 + "\n")
                f.write(f"Componente: {componente.upper()}\n")
                f.write(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Utilizador: {utilizador}\n")
                f.write("="*50 + "\n\n")
                f.write(relatorio)
            
            return nome_ficheiro
        except Exception as e:
            return None

class ProcessadorComandosAdmin:
    """Processador de comandos administrativos"""
    
    def __init__(self, gestor_utilizadores, gestor_relatorios):
        self.gestor_utilizadores = gestor_utilizadores
        self.gestor_relatorios = gestor_relatorios
    
    def processar_comando(self, comando_json):
        try:
            comando = json.loads(comando_json)
            tipo = comando.get('tipo')
            dados = comando.get('dados', {})
            
            if tipo == 'login':
                return self.processar_login(dados)
            elif tipo == 'ping':
                return json.dumps({'sucesso': True, 'mensagem': 'pong'})
            else:
                return json.dumps({'sucesso': False, 'erro': 'Comando desconhecido'})
                
        except Exception as e:
            return json.dumps({'sucesso': False, 'erro': str(e)})
    
    def processar_login(self, dados):
        username = dados.get('username')
        password = dados.get('password')
        
        resultado = self.gestor_utilizadores.autenticar(username, password)
        
        if resultado:
            return json.dumps({
                'sucesso': True,
                'utilizador': resultado
            })
        else:
            return json.dumps({
                'sucesso': False,
                'erro': 'Credenciais inválidas'
            })

class VPNServer:
    def __init__(self):
        self.porta_tcp = 7001
        self.porta_udp = 6002
        self.host = 'localhost'
        
        self.socket_tcp = None
        self.socket_udp = None
        self.cliente_tcp = None
        
        self.cliente_ligado = False
        self.a_executar = True
        
        self.gestor_cripto = GestorCriptografia()
        self.monitor_tcp = MonitorTCP("VPN Server")
        
        # Gestão administrativa
        self.gestor_utilizadores_servidor = GestorUtilizadoresServidor()
        self.gestor_relatorios_servidor = GestorRelatoriosServidor()
        self.processador_admin = ProcessadorComandosAdmin(
            self.gestor_utilizadores_servidor,
            self.gestor_relatorios_servidor
        )
        
        self.configuracoes = {
            'algoritmo_criptografia': 'cesar',
            'usar_hmac': True
        }
        
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Cria pasta de debug
        os.makedirs("debug_cripto", exist_ok=True)
        
        print("VPN Server inicializado")
    
    def signal_handler(self, signum, frame):
        self.parar()
        sys.exit(0)
    
    def log_debug(self, mensagem):
        """Escreve no ficheiro de debug na pasta correta"""
        try:
            timestamp = time.strftime('%H:%M:%S')
            with open("debug_cripto/debug_cripto.txt", "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] VPN SERVER: {mensagem}\n")
        except:
            pass
    
    def inicializar_sockets(self):
        try:
            self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket_tcp.bind((self.host, self.porta_tcp))
            self.socket_tcp.listen(1)
            
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket_udp.settimeout(1.0)
            self.socket_udp.bind((self.host, self.porta_udp))
            
            print(f"Sockets inicializados - TCP:{self.porta_tcp}, UDP:{self.porta_udp}")
            return True
            
        except Exception as e:
            print(f"Erro ao inicializar sockets: {e}")
            return False
    
    def aguardar_cliente(self):
        try:
            print(f"Aguardando VPN Client...")
            self.cliente_tcp, endereco_cliente = self.socket_tcp.accept()
            self.cliente_ligado = True
            
            self.monitor_tcp.definir_socket_ativo(self.cliente_tcp, endereco_cliente)
            print(f"VPN Client conectado: {endereco_cliente}")
            
            if self.estabelecer_chaves_criptograficas():
                self.log_debug("Cliente conectado e chaves estabelecidas")
                return True
            else:
                return False
                
        except Exception as e:
            print(f"Erro ao aguardar cliente: {e}")
            return False
    
    def estabelecer_chaves_criptograficas(self):
        try:
            chave_publica_local = self.gestor_cripto.inicializar_diffie_hellman()
            
            dados_recebidos = self.receber_tcp_raw()
            if dados_recebidos:
                dados_cliente = json.loads(dados_recebidos)
                if dados_cliente.get('tipo') == 'diffie_hellman':
                    chave_publica_cliente = dados_cliente.get('chave_publica')
                    algoritmo_preferido = dados_cliente.get('algoritmo_preferido', 'cesar')
                    
                    algoritmo_a_usar = algoritmo_preferido if algoritmo_preferido in ['cesar', 'vigenere'] else 'cesar'
                    self.configuracoes['algoritmo_criptografia'] = algoritmo_a_usar
                    
                    mensagem_resposta = {
                        'tipo': 'diffie_hellman',
                        'chave_publica': chave_publica_local,
                        'algoritmo_aceito': algoritmo_a_usar,
                        'hmac_aceito': True
                    }
                    self.enviar_tcp_raw(json.dumps(mensagem_resposta))
                    
                    self.gestor_cripto.finalizar_diffie_hellman(chave_publica_cliente)
                    self.gestor_cripto.alterar_algoritmo(algoritmo_a_usar)
                    
                    self.log_debug(f"Chaves estabelecidas - Algoritmo: {algoritmo_a_usar.upper()}")
                    return True
            
            return False
            
        except Exception as e:
            print(f"Erro no estabelecimento de chaves: {e}")
            return False
    
    def enviar_tcp_raw(self, dados):
        if self.cliente_tcp and self.cliente_ligado:
            try:
                mensagem_completa = dados + '\n'
                bytes_dados = mensagem_completa.encode('utf-8')
                self.cliente_tcp.send(bytes_dados)
                self.monitor_tcp.registrar_envio(len(bytes_dados), True)
                return True
            except Exception as e:
                self.cliente_ligado = False
                self.monitor_tcp.conexao_perdida()
                return False
        return False
    
    def receber_tcp_raw(self):
        if self.cliente_tcp and self.cliente_ligado:
            try:
                dados_recebidos = ""
                while '\n' not in dados_recebidos:
                    chunk = self.cliente_tcp.recv(1024).decode('utf-8')
                    if not chunk:
                        return None
                    dados_recebidos += chunk
                
                bytes_recebidos = len(dados_recebidos.encode('utf-8'))
                self.monitor_tcp.registrar_recepcao(bytes_recebidos, True)
                
                return dados_recebidos.rstrip('\n')
                
            except Exception as e:
                self.cliente_ligado = False
                self.monitor_tcp.conexao_perdida()
                return None
        return None
    
    def receber_tcp_criptografado(self):
        if not self.cliente_ligado:
            return None
        
        try:
            dados_recebidos = ""
            while '\n' not in dados_recebidos:
                chunk = self.cliente_tcp.recv(1024).decode('utf-8')
                if not chunk:
                    return None
                dados_recebidos += chunk
            
            pacote = json.loads(dados_recebidos.rstrip('\n'))
            
            self.log_debug("Pacote TCP recebido do VPN Client")
            
            if pacote.get('tipo') == 'texto_claro':
                mensagem = pacote['mensagem']
                self.log_debug(f"Mensagem texto claro: '{mensagem}'")
                return f"[TEXTO_CLARO]{mensagem}"
            
            elif pacote.get('tipo') == 'criptografado':
                mensagem_cifrada = pacote['mensagem_cifrada']
                hash_esperado = pacote['hash_integridade']
                nonce = pacote.get('nonce')
                algoritmo = pacote.get('algoritmo', self.configuracoes['algoritmo_criptografia'])
                hmac_esperado = pacote.get('hmac_autenticacao')
                
                self.log_debug(f"Mensagem criptografada recebida com {algoritmo.upper()}: '{mensagem_cifrada}' nonce: {nonce}")
                
                mensagem_decifrada, integridade_ok, autenticacao_ok = self.gestor_cripto.decifrar_mensagem(
                    mensagem_cifrada, hash_esperado, nonce, algoritmo, hmac_esperado
                )
                
                if integridade_ok and autenticacao_ok:
                    self.log_debug(f"Mensagem decifrada: '{mensagem_decifrada}'")
                    return mensagem_decifrada
                else:
                    self.log_debug("Falha na verificação de integridade/autenticação")
                    return None
            
            return None
                
        except Exception as e:
            self.cliente_ligado = False
            self.monitor_tcp.conexao_perdida()
            return None
    
    def processar_tcp(self):
        while self.a_executar and self.cliente_ligado:
            try:
                mensagem = self.receber_tcp_criptografado()
                
                if mensagem:
                    self.encaminhar_para_udp2(mensagem)
                else:
                    self.cliente_ligado = False
                    self.monitor_tcp.conexao_perdida()
                    break
                    
            except Exception as e:
                if self.a_executar:
                    self.cliente_ligado = False
                    self.monitor_tcp.conexao_perdida()
                    break
    
    def processar_udp(self):
        while self.a_executar:
            try:
                dados, endereco = self.socket_udp.recvfrom(1024)
                mensagem = dados.decode('utf-8')
                
                if mensagem.startswith('[CONFIG]'):
                    self.processar_comando_configuracao(mensagem[8:])
                    continue
                
                if mensagem.startswith('[MONITOR]'):
                    self.processar_comando_monitor(mensagem[9:], endereco)
                    continue
                
                if mensagem.startswith('[ADMIN]'):
                    self.processar_comando_admin(mensagem[7:], endereco)
                    continue
                
                # Mensagem normal para encaminhar
                eh_texto_claro = mensagem.startswith('[TEXTO_CLARO]')
                if eh_texto_claro:
                    mensagem = mensagem[13:]
                
                if self.cliente_ligado:
                    self.enviar_tcp_criptografado(mensagem, eh_texto_claro)
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.a_executar:
                    pass  # Silencia erros
    
    def processar_comando_configuracao(self, comando):
        try:
            partes = comando.split('|')
            if len(partes) >= 2:
                tipo_comando = partes[0]
                valor = partes[1]
                
                if tipo_comando == 'algoritmo':
                    if valor.lower() in ['cesar', 'vigenere']:
                        self.configuracoes['algoritmo_criptografia'] = valor.lower()
                        self.gestor_cripto.alterar_algoritmo(valor.lower())
                        self.log_debug(f"Algoritmo alterado para {valor.upper()}")
        except Exception as e:
            pass
    
    def processar_comando_monitor(self, comando, endereco_origem):
        try:
            print(f"Processando comando monitor: {comando}")
            
            if comando == 'relatorio':
                relatorio = self.monitor_tcp.gerar_relatorio_detalhado()
                
                resposta = f"[RELATORIO_TCP]{relatorio}"
                sock_resposta = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_resposta.sendto(resposta.encode('utf-8'), endereco_origem)
                sock_resposta.close()
                
                print("✓ Relatório TCP enviado")
                
            elif comando == 'stats':
                stats = self.monitor_tcp.obter_estatisticas_conexao()
                resposta = f"[STATS_TCP]{json.dumps(stats)}"
                
                sock_resposta = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_resposta.sendto(resposta.encode('utf-8'), endereco_origem)
                sock_resposta.close()
                
                print("✓ Estatísticas TCP enviadas")
            
        except Exception as e:
            print(f"Erro ao processar comando monitor: {e}")
    
    def processar_comando_admin(self, comando, endereco_origem):
        """Processa comandos administrativos e responde"""
        try:
            resposta_json = self.processador_admin.processar_comando(comando)
            
            resposta_completa = f"[ADMIN_RESP]{resposta_json}"
            sock_resposta = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_resposta.sendto(resposta_completa.encode('utf-8'), endereco_origem)
            sock_resposta.close()
            
        except Exception as e:
            try:
                erro_json = json.dumps({'sucesso': False, 'erro': str(e)})
                resposta_erro = f"[ADMIN_RESP]{erro_json}"
                sock_resposta = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_resposta.sendto(resposta_erro.encode('utf-8'), endereco_origem)
                sock_resposta.close()
            except:
                pass
    
    def enviar_tcp_criptografado(self, mensagem, eh_texto_claro=False):
        if not self.cliente_ligado:
            return
        
        try:
            if eh_texto_claro:
                pacote = {
                    'tipo': 'texto_claro',
                    'mensagem': mensagem,
                    'timestamp': time.time()
                }
            else:
                mensagem_cifrada, hash_integridade, nonce, algoritmo, hmac_autenticacao = self.gestor_cripto.cifrar_mensagem(mensagem)
                
                pacote = {
                    'tipo': 'criptografado',
                    'mensagem_cifrada': mensagem_cifrada,
                    'hash_integridade': hash_integridade,
                    'nonce': nonce,
                    'algoritmo': algoritmo,
                    'hmac_autenticacao': hmac_autenticacao,
                    'timestamp': time.time()
                }
            
            self.enviar_tcp_raw(json.dumps(pacote))
            
        except Exception as e:
            self.cliente_ligado = False
            self.monitor_tcp.conexao_perdida()
    
    def encaminhar_para_udp2(self, mensagem):
        try:
            self.log_debug(f"Encaminhando para ProgUDP2: '{mensagem}'")
            
            dados = mensagem.encode('utf-8')
            self.socket_udp.sendto(dados, (self.host, 5002))
            
        except Exception as e:
            pass
    
    def parar(self):
        self.a_executar = False
        
        if self.monitor_tcp:
            self.monitor_tcp.parar()
        
        if self.cliente_tcp:
            try:
                self.cliente_tcp.close()
            except:
                pass
        
        if self.socket_tcp:
            try:
                self.socket_tcp.close()
            except:
                pass
        
        if self.socket_udp:
            try:
                self.socket_udp.close()
            except:
                pass
    
    def executar(self):
        print("Iniciando VPN Server...")
        
        if not self.inicializar_sockets():
            return
        
        thread_udp = threading.Thread(target=self.processar_udp, daemon=True)
        thread_udp.start()
        
        print("VPN Server pronto")
        
        try:
            while self.a_executar:
                if not self.cliente_ligado:
                    if self.aguardar_cliente():
                        thread_tcp = threading.Thread(target=self.processar_tcp, daemon=True)
                        thread_tcp.start()
                else:
                    time.sleep(1)
        
        except KeyboardInterrupt:
            pass
        finally:
            self.parar()

def main():
    try:
        vpn_server = VPNServer()
        vpn_server.executar()
    except Exception as e:
        pass
    finally:
        pass

if __name__ == "__main__":
    main()