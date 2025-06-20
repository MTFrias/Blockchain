#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProgUDP1.py - Cliente UDP 1
Programa que simula um cliente UDP que comunica através da VPN
"""

import socket
import threading
import time
import sys
import signal

class ProgUDP1:
    def __init__(self):
        """
        Inicializa o cliente UDP1
        """
        # Configurações de rede
        self.porta_local = 5001  # Porta onde este programa escuta
        self.porta_vpn_client = 6001  # Porta do VPN Client
        self.host = 'localhost'
        
        # Socket UDP
        self.socket_udp = None
        
        # Estado do programa
        self.a_executar = True
        
        # Configura handler para SIGTERM (para ser parado pelo gestor)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        print("ProgUDP1 inicializado (gerido pelo sistema)")
        print(f"Porta local: {self.porta_local}")
        print(f"Porta VPN Client: {self.porta_vpn_client}")
    
    def signal_handler(self, signum, frame):
        """
        Handler para sinais do sistema
        """
        print("ProgUDP1 recebeu sinal de paragem")
        self.parar()
        sys.exit(0)
    
    def inicializar_socket(self):
        """
        Inicializa o socket UDP para comunicação
        """
        try:
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Permite reutilizar o endereço
            self.socket_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Define timeout para operações de socket
            self.socket_udp.settimeout(1.0)
            # Vincula o socket à porta local
            self.socket_udp.bind((self.host, self.porta_local))
            print(f"Socket UDP vinculado à porta {self.porta_local}")
            return True
        except Exception as e:
            print(f"Erro ao inicializar socket: {e}")
            return False
    
    def escutar_mensagens(self):
        """
        Thread que escuta mensagens recebidas via UDP
        """
        print("Iniciando escuta de mensagens...")
        
        while self.a_executar:
            try:
                # Recebe dados via UDP
                dados, endereco = self.socket_udp.recvfrom(1024)
                mensagem = dados.decode('utf-8')
                
                # Verifica se é mensagem de texto claro
                if mensagem.startswith('[TEXTO_CLARO]'):
                    mensagem_limpa = mensagem[13:]  # Remove prefixo
                    print(f"Mensagem TEXTO CLARO recebida de {endereco}: {mensagem_limpa}")
                else:
                    print(f"Mensagem CRIPTOGRAFADA recebida de {endereco}: {mensagem}")
                
                # Log da mensagem com timestamp
                timestamp = time.strftime('%H:%M:%S')
                print(f"[{timestamp}] Nova mensagem disponível")
                
            except socket.timeout:
                # Timeout normal, continua o loop
                continue
            except Exception as e:
                if self.a_executar:
                    print(f"Erro ao receber mensagem: {e}")
    
    def enviar_mensagem(self, mensagem):
        """
        Envia mensagem via UDP para o VPN Client
        
        Args:
            mensagem (str): Mensagem a ser enviada
        """
        try:
            # Converte mensagem para bytes
            dados = mensagem.encode('utf-8')
            
            # Envia para o VPN Client
            self.socket_udp.sendto(dados, (self.host, self.porta_vpn_client))
            timestamp = time.strftime('%H:%M:%S')
            print(f"[{timestamp}] Mensagem enviada para VPN Client: {mensagem}")
            
        except Exception as e:
            print(f"Erro ao enviar mensagem: {e}")
    
    def mostrar_estado(self):
        """
        Mostra informações sobre o estado atual do programa
        """
        print("\n" + "-"*30)
        print("ESTADO DO PROGUDP1")
        print("-"*30)
        print(f"Porta local: {self.porta_local}")
        print(f"Porta VPN Client: {self.porta_vpn_client}")
        print(f"Estado: {'Ativo' if self.a_executar else 'Inativo'}")
        print(f"Socket: {'Conectado' if self.socket_udp else 'Desconectado'}")
        print("-"*30)
    
    def parar(self):
        """
        Para o programa e fecha recursos
        """
        print("Parando ProgUDP1...")
        self.a_executar = False
        
        # Fecha socket se estiver aberto
        if self.socket_udp:
            try:
                self.socket_udp.close()
                print("Socket UDP fechado")
            except Exception as e:
                print(f"Erro ao fechar socket: {e}")
    
    def executar(self):
        """
        Método principal que executa o programa
        """
        print("Iniciando ProgUDP1...")
        
        # Inicializa socket
        if not self.inicializar_socket():
            print("Falha ao inicializar socket. Programa terminado.")
            return
        
        # Inicia thread para escutar mensagens
        thread_escuta = threading.Thread(target=self.escutar_mensagens, daemon=True)
        thread_escuta.start()
        
        # Aguarda um momento para a thread inicializar
        time.sleep(0.5)
        
        print("ProgUDP1 em execução - aguardando mensagens...")
        print("Pronto para receber mensagens via VPN")
        
        try:
            # Loop principal - mantém o programa vivo
            while self.a_executar:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nProgUDP1 interrompido pelo utilizador")
        except Exception as e:
            print(f"Erro durante execução: {e}")
        finally:
            # Garantir que recursos são libertados
            self.parar()

def main():
    """
    Função principal do programa
    """
    try:
        # Cria e executa instância do ProgUDP1
        prog_udp1 = ProgUDP1()
        prog_udp1.executar()
        
    except KeyboardInterrupt:
        print("\nPrograma interrompido pelo utilizador")
    except Exception as e:
        print(f"Erro fatal: {e}")
    finally:
        print("ProgUDP1 terminado")

if __name__ == "__main__":
    main()