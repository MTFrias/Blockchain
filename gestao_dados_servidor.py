#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gestao_dados_servidor.py - Gestão de dados administrativos no VPN Server
"""

import os
import hashlib
import json
import time
from datetime import datetime

class GestorUtilizadoresServidor:
    """
    Gere utilizadores no lado do servidor VPN
    """
    
    def __init__(self, ficheiro_utilizadores="vpn_utilizadores/utilizadores.txt"):
        self.ficheiro_utilizadores = ficheiro_utilizadores
        self.utilizadores = {}
        self.sessoes_ativas = {}
        
        # Cria pasta se não existir
        os.makedirs("vpn_utilizadores", exist_ok=True)
        
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
                print(f"VPN Server: Carregados {len(self.utilizadores)} utilizadores")
            else:
                print("VPN Server: Criando utilizador admin padrão...")
                self.criar_utilizador("admin", "admin123", "administrador")
        except Exception as e:
            print(f"VPN Server: Erro ao carregar utilizadores: {e}")
    
    def guardar_utilizadores(self):
        try:
            with open(self.ficheiro_utilizadores, 'w', encoding='utf-8') as f:
                f.write("# Ficheiro de utilizadores VPN (armazenado no servidor)\n")
                f.write("# Formato: username|password_hash|role|data_criacao\n")
                f.write("# Roles: utilizador, administrador\n\n")
                
                for username, dados in self.utilizadores.items():
                    linha = f"{username}|{dados['password_hash']}|{dados['role']}|{dados['data_criacao']}\n"
                    f.write(linha)
                    
            print("VPN Server: Utilizadores guardados com sucesso")
        except Exception as e:
            print(f"VPN Server: Erro ao guardar utilizadores: {e}")
    
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
            if time.time() - sessao['ultimo_acesso'] < 1800:  # 30 minutos
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
    
    def listar_utilizadores(self):
        return [
            {
                'username': username,
                'role': dados['role'],
                'data_criacao': dados['data_criacao']
            }
            for username, dados in self.utilizadores.items()
        ]
    
    def remover_utilizador(self, username):
        if username in self.utilizadores:
            del self.utilizadores[username]
            self.guardar_utilizadores()
            return True
        return False

class GestorRelatoriosServidor:
    """
    Gere relatórios e logs no lado do servidor VPN
    """
    
    def __init__(self):
        self.pasta_relatorios = "vpn_relatorios"
        os.makedirs(self.pasta_relatorios, exist_ok=True)
    
    def guardar_relatorio_tcp(self, componente, relatorio, utilizador):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome_ficheiro = f"relatorio_tcp_{componente}_{timestamp}.txt"
            caminho_completo = os.path.join(self.pasta_relatorios, nome_ficheiro)
            
            with open(caminho_completo, 'w', encoding='utf-8') as f:
                f.write("RELATÓRIO TCP DETALHADO (VPN SERVER)\n")
                f.write("="*50 + "\n")
                f.write(f"Componente: {componente.upper()}\n")
                f.write(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Utilizador: {utilizador}\n")
                f.write(f"Armazenado em: VPN Server\n")
                f.write("="*50 + "\n\n")
                f.write(relatorio)
                f.write(f"\n\nRelatório gerado automaticamente pelo VPN Server\n")
            
            print(f"VPN Server: Relatório guardado: {nome_ficheiro}")
            return nome_ficheiro
            
        except Exception as e:
            print(f"VPN Server: Erro ao guardar relatório: {e}")
            return None
    
    def guardar_estatisticas_tcp(self, componente, stats_formatadas, utilizador):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome_ficheiro = f"stats_tcp_{componente}_{timestamp}.txt"
            caminho_completo = os.path.join(self.pasta_relatorios, nome_ficheiro)
            
            with open(caminho_completo, 'w', encoding='utf-8') as f:
                f.write("ESTATÍSTICAS TCP (VPN SERVER)\n")
                f.write("="*30 + "\n")
                f.write(f"Componente: {componente.upper()}\n")
                f.write(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Utilizador: {utilizador}\n")
                f.write("="*30 + "\n")
                f.write(stats_formatadas)
                f.write(f"\n\nEstatísticas geradas automaticamente pelo VPN Server\n")
            
            print(f"VPN Server: Estatísticas guardadas: {nome_ficheiro}")
            return nome_ficheiro
            
        except Exception as e:
            print(f"VPN Server: Erro ao guardar estatísticas: {e}")
            return None
    
    def guardar_comparacao_tcp(self, comparacao, utilizador):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome_ficheiro = f"comparacao_tcp_{timestamp}.txt"
            caminho_completo = os.path.join(self.pasta_relatorios, nome_ficheiro)
            
            with open(caminho_completo, 'w', encoding='utf-8') as f:
                f.write("COMPARAÇÃO TCP CLIENT vs SERVER (VPN SERVER)\n")
                f.write("="*50 + "\n")
                f.write(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Utilizador: {utilizador}\n")
                f.write("="*50 + "\n")
                f.write(comparacao)
                f.write(f"\n\nComparação gerada automaticamente pelo VPN Server\n")
            
            print(f"VPN Server: Comparação guardada: {nome_ficheiro}")
            return nome_ficheiro
            
        except Exception as e:
            print(f"VPN Server: Erro ao guardar comparação: {e}")
            return None
    
    def listar_relatorios(self):
        try:
            if os.path.exists(self.pasta_relatorios):
                ficheiros = []
                for ficheiro in os.listdir(self.pasta_relatorios):
                    if ficheiro.endswith('.txt'):
                        caminho = os.path.join(self.pasta_relatorios, ficheiro)
                        stat = os.stat(caminho)
                        ficheiros.append({
                            'nome': ficheiro,
                            'tamanho': stat.st_size,
                            'modificado': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        })
                return sorted(ficheiros, key=lambda x: x['modificado'], reverse=True)
            return []
        except Exception as e:
            print(f"VPN Server: Erro ao listar relatórios: {e}")
            return []

class ProcessadorComandosAdmin:
    """
    Processa comandos administrativos no servidor VPN
    """
    
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
            elif tipo == 'criar_utilizador':
                return self.processar_criar_utilizador(dados)
            elif tipo == 'listar_utilizadores':
                return self.processar_listar_utilizadores(dados)
            elif tipo == 'remover_utilizador':
                return self.processar_remover_utilizador(dados)
            elif tipo == 'guardar_relatorio':
                return self.processar_guardar_relatorio(dados)
            elif tipo == 'listar_relatorios':
                return self.processar_listar_relatorios(dados)
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
    
    def processar_criar_utilizador(self, dados):
        token = dados.get('token_sessao')
        sessao = self.gestor_utilizadores.validar_sessao(token)
        
        if not sessao:
            return json.dumps({'sucesso': False, 'erro': 'Sessão inválida'})
        
        username = dados.get('username')
        password = dados.get('password')
        role = dados.get('role')
        
        sucesso = self.gestor_utilizadores.criar_utilizador(username, password, role)
        
        return json.dumps({
            'sucesso': sucesso,
            'erro': 'Utilizador já existe' if not sucesso else None
        })
    
    def processar_listar_utilizadores(self, dados):
        token = dados.get('token_sessao')
        sessao = self.gestor_utilizadores.validar_sessao(token)
        
        if not sessao:
            return json.dumps({'sucesso': False, 'erro': 'Sessão inválida'})
        
        utilizadores = self.gestor_utilizadores.listar_utilizadores()
        
        return json.dumps({
            'sucesso': True,
            'utilizadores': utilizadores
        })
    
    def processar_remover_utilizador(self, dados):
        token = dados.get('token_sessao')
        sessao = self.gestor_utilizadores.validar_sessao(token)
        
        if not sessao:
            return json.dumps({'sucesso': False, 'erro': 'Sessão inválida'})
        
        username = dados.get('username')
        
        if username == sessao['username']:
            return json.dumps({'sucesso': False, 'erro': 'Não pode remover o próprio utilizador'})
        
        sucesso = self.gestor_utilizadores.remover_utilizador(username)
        
        return json.dumps({
            'sucesso': sucesso,
            'erro': 'Utilizador não encontrado' if not sucesso else None
        })
    
    def processar_guardar_relatorio(self, dados):
        token = dados.get('token_sessao')
        sessao = self.gestor_utilizadores.validar_sessao(token)
        
        if not sessao:
            return json.dumps({'sucesso': False, 'erro': 'Sessão inválida'})
        
        tipo_relatorio = dados.get('tipo_relatorio')
        componente = dados.get('componente')
        conteudo = dados.get('conteudo')
        
        if tipo_relatorio == 'relatorio_completo':
            ficheiro = self.gestor_relatorios.guardar_relatorio_tcp(
                componente, conteudo, sessao['username']
            )
        elif tipo_relatorio == 'estatisticas':
            ficheiro = self.gestor_relatorios.guardar_estatisticas_tcp(
                componente, conteudo, sessao['username']
            )
        elif tipo_relatorio == 'comparacao':
            ficheiro = self.gestor_relatorios.guardar_comparacao_tcp(
                conteudo, sessao['username']
            )
        else:
            return json.dumps({'sucesso': False, 'erro': 'Tipo de relatório inválido'})
        
        return json.dumps({
            'sucesso': ficheiro is not None,
            'ficheiro': ficheiro,
            'erro': 'Erro ao guardar ficheiro' if ficheiro is None else None
        })
    
    def processar_listar_relatorios(self, dados):
        token = dados.get('token_sessao')
        sessao = self.gestor_utilizadores.validar_sessao(token)
        
        if not sessao:
            return json.dumps({'sucesso': False, 'erro': 'Sessão inválida'})
        
        relatorios = self.gestor_relatorios.listar_relatorios()
        
        return json.dumps({
            'sucesso': True,
            'relatorios': relatorios
        })