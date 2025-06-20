#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProgUDP2_corrigido.py - Cliente UDP 2 corrigido
"""

import socket
import threading
import time
import sys
import signal
import os

class ProgUDP2:
    def __init__(self):
        self.porta_local = 5002
        self.porta_vpn_server = 6002
        self.host = 'localhost'
        
        self.socket_udp = None
        self.a_executar = True
        self.contador_mensagens = 0
        
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Cria pasta de debug correta
        os.makedirs("debug_cripto", exist_ok=True)
        
        self.mostrar_cabecalho()
    
    def mostrar_cabecalho(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("="*80)
        print("           PROG UDP2 - DEMONSTRADOR CRIPTOGRAFIA VPN")
        print("="*80)
        print(f"Porta local: {self.porta_local}")
        print(f"Status: Aguardando mensagens através do túnel VPN...")
        print("="*80)
        print("FLUXO: Gestor -> VPN Client -> [TCP CRIPTOGRAFADO] -> VPN Server -> ProgUDP2")
        print("="*80)
    
    def signal_handler(self, signum, frame):
        print("\nProgUDP2 parado")
        self.parar()
        sys.exit(0)
    
    def log_debug(self, mensagem):
        """Escreve no ficheiro de debug na pasta correta"""
        try:
            timestamp = time.strftime('%H:%M:%S')
            with open("debug_cripto/debug_cripto.txt", "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] PROG UDP2: {mensagem}\n")
        except:
            pass
    
    def inicializar_socket(self):
        try:
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket_udp.settimeout(1.0)
            self.socket_udp.bind((self.host, self.porta_local))
            print(f"Socket UDP vinculado à porta {self.porta_local}")
            print("Pronto para receber mensagens!")
            print("-"*80)
            return True
        except Exception as e:
            print(f"Erro ao inicializar socket: {e}")
            return False
    
    def extrair_dados_criptografados_do_debug(self):
        """Extrai dados criptografados do ficheiro de debug"""
        try:
            debug_path = "debug_cripto/debug_cripto.txt"
            if os.path.exists(debug_path):
                with open(debug_path, "r", encoding='utf-8', errors='ignore') as f:
                    linhas = f.readlines()
                
                # Procura pela última mensagem criptografada
                for linha in reversed(linhas):
                    if "VPN SERVER: Mensagem criptografada recebida" in linha:
                        if "'" in linha:
                            inicio = linha.find("'") + 1
                            fim = linha.find("'", inicio)
                            if inicio > 0 and fim > inicio:
                                dados_criptografados = linha[inicio:fim]
                                dados_limpos = ''.join(c if ord(c) >= 32 and ord(c) <= 126 else '?' for c in dados_criptografados)
                                return dados_limpos
                        
        except Exception as e:
            pass
        
        return "Dados criptografados (indisponíveis)"
    
    def mostrar_mensagem_criptografada(self, mensagem_original, dados_criptografados):
        print("CRIPTOGRAFIA PROCESSADA " + "="*56)
        print("DADOS CRIPTOGRAFADOS RECEBIDOS VIA TCP:")
        print(f"   +{'-'*60}+")
        print(f"   | {dados_criptografados[:58]:<58} |")
        if len(dados_criptografados) > 58:
            print(f"   | {dados_criptografados[58:116]:<58} |")
        if len(dados_criptografados) > 116:
            print(f"   | [...truncado...]                                          |")
        print(f"   +{'-'*60}+")
        print()
        print("MENSAGEM ORIGINAL (decifrada pelo VPN Server):")
        print(f"   +{'-'*60}+")
        print(f"   | {mensagem_original:<58} |")
        print(f"   +{'-'*60}+")
        print()
        print("• Esta mensagem foi criptografada com DESLOCAMENTO DINÂMICO")
        print("• VPN Server decifrou usando o nonce correto")
        print("• Consulte debug_cripto/debug_cripto.txt para detalhes")
        print("="*80)
    
    def mostrar_mensagem_texto_claro(self, mensagem):
        print("TEXTO CLARO DETECTADO " + "="*58)
        print("CONTEÚDO (enviado sem criptografia):")
        print(f"   +{'-'*60}+")
        print(f"   | {mensagem:<58} |")
        print(f"   +{'-'*60}+")
        print("NOTA: Esta mensagem não foi criptografada")
        print("="*80)
    
    def escutar_mensagens(self):
        while self.a_executar:
            try:
                dados, endereco = self.socket_udp.recvfrom(1024)
                mensagem = dados.decode('utf-8')
                
                self.contador_mensagens += 1
                timestamp = time.strftime('%H:%M:%S')
                
                self.log_debug(f"Mensagem recebida: '{mensagem}'")
                
                print("\n" + "="*80)
                print(f"NOVA MENSAGEM #{self.contador_mensagens}")
                print(f"Hora: {timestamp} | Origem: {endereco}")
                print("="*80)
                
                if mensagem.startswith('[TEXTO_CLARO]'):
                    mensagem_limpa = mensagem[13:]
                    self.mostrar_mensagem_texto_claro(mensagem_limpa)
                else:
                    dados_criptografados = self.extrair_dados_criptografados_do_debug()
                    self.mostrar_mensagem_criptografada(mensagem, dados_criptografados)
                
                print()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.a_executar:
                    pass
    
    def parar(self):
        self.a_executar = False
        
        if self.socket_udp:
            try:
                self.socket_udp.close()
            except:
                pass
    
    def executar(self):
        if not self.inicializar_socket():
            input("Pressione Enter para sair...")
            return
        
        thread_escuta = threading.Thread(target=self.escutar_mensagens, daemon=True)
        thread_escuta.start()
        
        time.sleep(0.5)
        
        try:
            while self.a_executar:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nProgUDP2 interrompido")
        finally:
            self.parar()

def main():
    try:
        prog_udp2 = ProgUDP2()
        prog_udp2.executar()
        
    except KeyboardInterrupt:
        print("\nPrograma interrompido")
    except Exception as e:
        pass
    finally:
        pass

if __name__ == "__main__":
    main()