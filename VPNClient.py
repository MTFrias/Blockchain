#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPNClient_corrigido.py - Cliente VPN corrigido com pastas corretas
"""

import socket
import threading
import json
import time
import sys
import signal
import os
from criptografia import GestorCriptografia
from monitor_tcp import MonitorTCP

class VPNClient:
    def __init__(self):
        self.porta_udp = 6001
        self.porta_tcp_server = 7001
        self.host = 'localhost'
        
        self.socket_udp = None
        self.socket_tcp = None
        
        self.ligado_servidor = False
        self.a_executar = True
        
        self.gestor_cripto = GestorCriptografia()
        self.monitor_tcp = MonitorTCP("VPN Client")
        
        self.configuracoes = {
            'algoritmo_criptografia': 'cesar',
            'usar_hmac': True
        }
        
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Cria pasta de debug correta
        os.makedirs("debug_cripto", exist_ok=True)
        
        print("VPN Client inicializado")
    
    def signal_handler(self, signum, frame):
        self.parar()
        sys.exit(0)
    
    def log_debug(self, mensagem):
        """Escreve no ficheiro de debug na pasta correta"""
        try:
            timestamp = time.strftime('%H:%M:%S')
            with open("debug_cripto/debug_cripto.txt", "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] VPN CLIENT: {mensagem}\n")
        except:
            pass
    
    def inicializar_sockets(self):
        try:
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket_udp.settimeout(1.0)
            self.socket_udp.bind((self.host, self.porta_udp))
            
            self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            print(f"Sockets inicializados - UDP:{self.porta_udp}")
            return True
            
        except Exception as e:
            print(f"Erro ao inicializar sockets: {e}")
            return False
    
    def ligar_servidor(self):
        tentativas = 0
        max_tentativas = 5
        
        while tentativas < max_tentativas and self.a_executar:
            try:
                print(f"Conectando ao VPN Server (tentativa {tentativas + 1})")
                self.socket_tcp.connect((self.host, self.porta_tcp_server))
                self.ligado_servidor = True
                
                endereco_servidor = (self.host, self.porta_tcp_server)
                self.monitor_tcp.definir_socket_ativo(self.socket_tcp, endereco_servidor)
                
                print("Conexão TCP estabelecida")
                
                if self.estabelecer_chaves_criptograficas():
                    print("VPN Client operacional")
                    return True
                else:
                    return False
                    
            except Exception as e:
                tentativas += 1
                if tentativas < max_tentativas:
                    time.sleep(3)
                    
        self.ligado_servidor = False
        self.monitor_tcp.conexao_perdida()
        return False
    
    def estabelecer_chaves_criptograficas(self):
        try:
            chave_publica_local = self.gestor_cripto.inicializar_diffie_hellman()
            
            mensagem_chave = {
                'tipo': 'diffie_hellman',
                'chave_publica': chave_publica_local,
                'algoritmo_preferido': self.configuracoes['algoritmo_criptografia'],
                'usar_hmac': self.configuracoes['usar_hmac']
            }
            
            dados_envio = json.dumps(mensagem_chave)
            if self.enviar_tcp_raw(dados_envio):
                self.monitor_tcp.registrar_envio(len(dados_envio), True)
            else:
                self.monitor_tcp.registrar_envio(len(dados_envio), False)
                return False
            
            resposta = self.receber_tcp_raw()
            if resposta:
                self.monitor_tcp.registrar_recepcao(len(resposta), True)
                
                dados_resposta = json.loads(resposta)
                if dados_resposta.get('tipo') == 'diffie_hellman':
                    chave_publica_servidor = dados_resposta.get('chave_publica')
                    algoritmo_aceito = dados_resposta.get('algoritmo_aceito', self.configuracoes['algoritmo_criptografia'])
                    
                    if algoritmo_aceito != self.configuracoes['algoritmo_criptografia']:
                        self.configuracoes['algoritmo_criptografia'] = algoritmo_aceito
                    
                    self.gestor_cripto.finalizar_diffie_hellman(chave_publica_servidor)
                    self.gestor_cripto.alterar_algoritmo(self.configuracoes['algoritmo_criptografia'])
                    
                    self.log_debug("Chaves Diffie-Hellman estabelecidas")
                    self.log_debug(f"Algoritmo ativo: {self.configuracoes['algoritmo_criptografia'].upper()}")
                    
                    return True
            else:
                self.monitor_tcp.registrar_recepcao(0, False)
            
            return False
            
        except Exception as e:
            return False
    
    def enviar_tcp_raw(self, dados):
        if self.socket_tcp and self.ligado_servidor:
            try:
                mensagem_completa = dados + '\n'
                bytes_dados = mensagem_completa.encode('utf-8')
                self.socket_tcp.send(bytes_dados)
                return True
            except Exception as e:
                self.ligado_servidor = False
                self.monitor_tcp.conexao_perdida()
                return False
        return False
    
    def receber_tcp_raw(self):
        if self.socket_tcp and self.ligado_servidor:
            try:
                dados_recebidos = ""
                while '\n' not in dados_recebidos:
                    chunk = self.socket_tcp.recv(1024).decode('utf-8')
                    if not chunk:
                        return None
                    dados_recebidos += chunk
                
                return dados_recebidos.rstrip('\n')
                
            except Exception as e:
                self.ligado_servidor = False
                self.monitor_tcp.conexao_perdida()
                return None
        return None
    
    def enviar_tcp_criptografado(self, mensagem, eh_texto_claro=False):
        if not self.ligado_servidor:
            return
        
        try:
            self.log_debug(f"Recebida mensagem UDP: '{mensagem}' - Texto claro: {eh_texto_claro}")
            
            if eh_texto_claro:
                pacote = {
                    'tipo': 'texto_claro',
                    'mensagem': mensagem,
                    'timestamp': time.time()
                }
                self.log_debug("Enviando via TCP sem criptografia")
            else:
                mensagem_cifrada, hash_integridade, nonce, algoritmo, hmac_autenticacao = self.gestor_cripto.cifrar_mensagem(mensagem)
                
                self.log_debug(f"Mensagem criptografada com {algoritmo.upper()}: '{mensagem_cifrada}' nonce: {nonce}")
                
                pacote = {
                    'tipo': 'criptografado',
                    'mensagem_cifrada': mensagem_cifrada,
                    'hash_integridade': hash_integridade,
                    'nonce': nonce,
                    'algoritmo': algoritmo,
                    'hmac_autenticacao': hmac_autenticacao,
                    'timestamp': time.time()
                }
            
            dados_pacote = json.dumps(pacote) + '\n'
            bytes_enviados = len(dados_pacote.encode('utf-8'))
            
            if self.enviar_tcp_raw(json.dumps(pacote)):
                self.monitor_tcp.registrar_envio(bytes_enviados, True)
                self.log_debug(f"Pacote TCP enviado para VPN Server ({bytes_enviados} bytes)")
            else:
                self.monitor_tcp.registrar_envio(bytes_enviados, False)
            
        except Exception as e:
            self.ligado_servidor = False
            self.monitor_tcp.conexao_perdida()
    
    def receber_tcp_criptografado(self):
        if not self.ligado_servidor:
            return None
        
        try:
            dados_recebidos = ""
            while '\n' not in dados_recebidos:
                chunk = self.socket_tcp.recv(1024).decode('utf-8')
                if not chunk:
                    self.monitor_tcp.registrar_recepcao(0, False)
                    return None
                dados_recebidos += chunk
            
            bytes_recebidos = len(dados_recebidos.encode('utf-8'))
            self.monitor_tcp.registrar_recepcao(bytes_recebidos, True)
            
            pacote = json.loads(dados_recebidos.rstrip('\n'))
            
            if pacote.get('tipo') == 'texto_claro':
                mensagem = pacote['mensagem']
                return f"[TEXTO_CLARO]{mensagem}"
            
            elif pacote.get('tipo') == 'criptografado':
                mensagem_cifrada = pacote['mensagem_cifrada']
                hash_esperado = pacote['hash_integridade']
                nonce = pacote.get('nonce')
                algoritmo = pacote.get('algoritmo', self.configuracoes['algoritmo_criptografia'])
                hmac_esperado = pacote.get('hmac_autenticacao')
                
                mensagem_decifrada, integridade_ok, autenticacao_ok = self.gestor_cripto.decifrar_mensagem(
                    mensagem_cifrada, hash_esperado, nonce, algoritmo, hmac_esperado
                )
                
                if integridade_ok and autenticacao_ok:
                    return mensagem_decifrada
                else:
                    return None
            
            return None
                
        except Exception as e:
            self.ligado_servidor = False
            self.monitor_tcp.conexao_perdida()
            return None
    
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
                
                eh_texto_claro = mensagem.startswith('[TEXTO_CLARO]')
                if eh_texto_claro:
                    mensagem = mensagem[13:]
                
                if self.ligado_servidor:
                    self.enviar_tcp_criptografado(mensagem, eh_texto_claro)
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.a_executar:
                    pass
    
    def processar_tcp(self):
        while self.a_executar and self.ligado_servidor:
            try:
                mensagem = self.receber_tcp_criptografado()
                
                if mensagem:
                    self.encaminhar_para_udp1(mensagem)
                else:
                    self.ligado_servidor = False
                    self.monitor_tcp.conexao_perdida()
                    break
                    
            except Exception as e:
                if self.a_executar:
                    self.ligado_servidor = False
                    self.monitor_tcp.conexao_perdida()
                    break
    
    def encaminhar_para_udp1(self, mensagem):
        try:
            dados = mensagem.encode('utf-8')
            self.socket_udp.sendto(dados, (self.host, 5001))
            
        except Exception as e:
            pass
    
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
                
                elif tipo_comando == 'hmac':
                    self.configuracoes['usar_hmac'] = valor.lower() == 'true'
                    self.gestor_cripto.usar_hmac = self.configuracoes['usar_hmac']
            
        except Exception as e:
            pass
    
    def processar_comando_monitor(self, comando, endereco_origem):
        try:
            if comando == 'relatorio':
                relatorio = self.monitor_tcp.gerar_relatorio_detalhado()
                
                resposta = f"[RELATORIO_TCP]{relatorio}"
                sock_resposta = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_resposta.sendto(resposta.encode('utf-8'), endereco_origem)
                sock_resposta.close()
                
            elif comando == 'stats':
                stats = self.monitor_tcp.obter_estatisticas_conexao()
                resposta = f"[STATS_TCP]{json.dumps(stats)}"
                
                sock_resposta = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_resposta.sendto(resposta.encode('utf-8'), endereco_origem)
                sock_resposta.close()
            
        except Exception as e:
            pass
    
    def parar(self):
        self.a_executar = False
        
        if self.monitor_tcp:
            self.monitor_tcp.parar()
        
        if self.socket_udp:
            try:
                self.socket_udp.close()
            except:
                pass
        
        if self.socket_tcp:
            try:
                self.socket_tcp.close()
            except:
                pass
    
    def executar(self):
        print("Iniciando VPN Client...")
        
        if not self.inicializar_sockets():
            return
        
        if not self.ligar_servidor():
            return
        
        threads = [
            threading.Thread(target=self.processar_udp, daemon=True),
            threading.Thread(target=self.processar_tcp, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        print("VPN Client pronto")
        
        try:
            while self.a_executar:
                time.sleep(1)
                
                if not self.ligado_servidor and self.a_executar:
                    if self.ligar_servidor():
                        thread_tcp = threading.Thread(target=self.processar_tcp, daemon=True)
                        thread_tcp.start()
        
        except KeyboardInterrupt:
            pass
        finally:
            self.parar()

def main():
    try:
        vpn_client = VPNClient()
        vpn_client.executar()
    except Exception as e:
        pass
    finally:
        pass

if __name__ == "__main__":
    main()