#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gestor_utilizadores_remoto.py - Sistema de utilizadores remoto apenas
Conecta diretamente ao VPN Server sem fallback
"""

import socket
import json
import time
from datetime import datetime

class GestorUtilizadoresRemoto:
    """
    Gestor de utilizadores que conecta apenas ao VPN Server
    """
    
    def __init__(self, comunicador_vpn=None, max_tentativas=5):
        self.comunicador = comunicador_vpn
        self.max_tentativas = max_tentativas
        self.token_sessao = None
        self.servidor_disponivel = False
        self.utilizador_atual = None
        
        self.host = 'localhost'
        self.porta_servidor = 6002
        self.timeout_conexao = 10.0
        
        print("Gestor Utilizadores Remoto: Inicializado (apenas modo remoto)")
        self._verificar_servidor_disponivel()
    
    def _verificar_servidor_disponivel(self, tentativas=3):
        print("Verificando disponibilidade do VPN Server...")
        
        for tentativa in range(tentativas):
            try:
                comando_teste = {
                    'tipo': 'ping',
                    'timestamp': time.time()
                }
                
                if self.comunicador:
                    resposta = self._enviar_comando_com_timeout(comando_teste, timeout=5.0)
                    if resposta and resposta.get('sucesso', False):
                        self.servidor_disponivel = True
                        print("✓ VPN Server: DISPONÍVEL")
                        return True
                
                print(f"✗ Tentativa {tentativa + 1}/{tentativas} falhada")
                if tentativa < tentativas - 1:
                    time.sleep(2)
                    
            except Exception as e:
                print(f"✗ Erro na tentativa {tentativa + 1}: {e}")
                if tentativa < tentativas - 1:
                    time.sleep(2)
        
        self.servidor_disponivel = False
        print("✗ VPN Server: INDISPONÍVEL")
        return False
    
    def _enviar_comando_com_timeout(self, comando, timeout=10.0):
        if not self.comunicador:
            raise Exception("Comunicador não disponível")
        
        timeout_original = None
        if hasattr(self.comunicador, 'socket_resposta') and self.comunicador.socket_resposta:
            timeout_original = self.comunicador.socket_resposta.gettimeout()
            self.comunicador.socket_resposta.settimeout(timeout)
        
        try:
            resposta = self.comunicador.enviar_comando_admin(comando)
            return resposta
        finally:
            if timeout_original is not None and hasattr(self.comunicador, 'socket_resposta') and self.comunicador.socket_resposta:
                self.comunicador.socket_resposta.settimeout(timeout_original)
    
    def aguardar_servidor_disponivel(self, timeout_total=30):
        print(f"Aguardando VPN Server ficar disponível (timeout: {timeout_total}s)...")
        
        inicio = time.time()
        while time.time() - inicio < timeout_total:
            if self._verificar_servidor_disponivel(tentativas=1):
                return True
            
            print("Aguardando servidor... (tentando novamente em 3s)")
            time.sleep(3)
        
        print(f"✗ Timeout: Servidor não ficou disponível em {timeout_total}s")
        return False
    
    def autenticar(self, username, password, aguardar_servidor=True):
        if not self.servidor_disponivel:
            if aguardar_servidor:
                print("Servidor não disponível. Tentando aguardar...")
                if not self.aguardar_servidor_disponivel():
                    raise Exception("VPN Server não está disponível")
            else:
                raise Exception("VPN Server não está disponível")
        
        print(f"Autenticando {username} no VPN Server...")
        
        try:
            comando = {
                'tipo': 'login',
                'dados': {
                    'username': username,
                    'password': password
                }
            }
            
            resposta = self._enviar_comando_com_timeout(comando, timeout=15.0)
            
            if resposta and resposta.get('sucesso'):
                utilizador = resposta.get('utilizador')
                self.token_sessao = utilizador.get('token_sessao')
                self.utilizador_atual = utilizador
                print(f"✓ Login remoto bem-sucedido para {username}")
                return utilizador
            else:
                erro = resposta.get('erro', 'Credenciais inválidas') if resposta else 'Sem resposta do servidor'
                print(f"✗ Login falhado: {erro}")
                return None
                
        except Exception as e:
            print(f"✗ Erro no login remoto: {e}")
            self.servidor_disponivel = False
            raise
    
    def criar_utilizador(self, username, password, role):
        if not self.servidor_disponivel or not self.token_sessao:
            raise Exception("Sessão não válida ou servidor indisponível")
        
        try:
            comando = {
                'tipo': 'criar_utilizador',
                'dados': {
                    'token_sessao': self.token_sessao,
                    'username': username,
                    'password': password,
                    'role': role
                }
            }
            
            resposta = self._enviar_comando_com_timeout(comando)
            
            if resposta and resposta.get('sucesso'):
                print(f"✓ Utilizador {username} criado no servidor remoto")
                return True
            else:
                erro = resposta.get('erro', 'Erro desconhecido') if resposta else 'Sem resposta'
                print(f"✗ Falha ao criar utilizador: {erro}")
                return False
                
        except Exception as e:
            print(f"✗ Erro ao criar utilizador: {e}")
            return False
    
    def listar_utilizadores(self):
        if not self.servidor_disponivel or not self.token_sessao:
            raise Exception("Sessão não válida ou servidor indisponível")
        
        try:
            comando = {
                'tipo': 'listar_utilizadores',
                'dados': {
                    'token_sessao': self.token_sessao
                }
            }
            
            resposta = self._enviar_comando_com_timeout(comando)
            
            if resposta and resposta.get('sucesso'):
                return resposta.get('utilizadores', [])
            else:
                erro = resposta.get('erro', 'Erro desconhecido') if resposta else 'Sem resposta'
                raise Exception(f"Falha ao listar utilizadores: {erro}")
                
        except Exception as e:
            print(f"✗ Erro ao listar utilizadores: {e}")
            raise
    
    def remover_utilizador(self, username):
        if not self.servidor_disponivel or not self.token_sessao:
            raise Exception("Sessão não válida ou servidor indisponível")
        
        try:
            comando = {
                'tipo': 'remover_utilizador',
                'dados': {
                    'token_sessao': self.token_sessao,
                    'username': username
                }
            }
            
            resposta = self._enviar_comando_com_timeout(comando)
            
            if resposta and resposta.get('sucesso'):
                print(f"✓ Utilizador {username} removido do servidor remoto")
                return True
            else:
                erro = resposta.get('erro', 'Erro desconhecido') if resposta else 'Sem resposta'
                print(f"✗ Falha ao remover utilizador: {erro}")
                return False
                
        except Exception as e:
            print(f"✗ Erro ao remover utilizador: {e}")
            return False
    
    def guardar_relatorio_servidor(self, tipo_relatorio, componente, conteudo):
        if not self.servidor_disponivel or not self.token_sessao:
            print("Servidor indisponível para guardar relatório")
            return None
        
        try:
            comando = {
                'tipo': 'guardar_relatorio',
                'dados': {
                    'token_sessao': self.token_sessao,
                    'tipo_relatorio': tipo_relatorio,
                    'componente': componente,
                    'conteudo': conteudo
                }
            }
            
            resposta = self._enviar_comando_com_timeout(comando)
            
            if resposta and resposta.get('sucesso'):
                ficheiro = resposta.get('ficheiro')
                print(f"✓ Relatório guardado no servidor: {ficheiro}")
                return ficheiro
            else:
                erro = resposta.get('erro', 'Erro desconhecido') if resposta else 'Sem resposta'
                print(f"✗ Falha ao guardar relatório: {erro}")
                return None
                
        except Exception as e:
            print(f"✗ Erro ao guardar relatório: {e}")
            return None
    
    def obter_estado(self):
        return {
            'servidor_disponivel': self.servidor_disponivel,
            'token_sessao': self.token_sessao is not None,
            'utilizador_atual': self.utilizador_atual.get('username') if self.utilizador_atual else None,
            'host': self.host,
            'porta': self.porta_servidor
        }
    
    def logout(self):
        self.token_sessao = None
        self.utilizador_atual = None
        print("Logout efetuado")

def testar_gestor_remoto():
    print("="*60)
    print("TESTE DO GESTOR DE UTILIZADORES REMOTO")
    print("="*60)
    
    try:
        gestor = GestorUtilizadoresRemoto(None)
        
        print("✓ Gestor inicializado")
        print("Nota: Para teste completo, VPN Server deve estar em execução")
        
    except Exception as e:
        print(f"✗ Erro durante teste: {e}")

if __name__ == "__main__":
    testar_gestor_remoto()