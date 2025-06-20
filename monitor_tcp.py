#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
monitor_tcp.py - Monitor de parâmetros TCP simplificado
"""

import time
import socket
import threading
import json
from collections import deque
from datetime import datetime

class MonitorTCP:
    def __init__(self, nome_componente="Monitor"):
        self.nome_componente = nome_componente
        
        # Contadores básicos
        self.bytes_enviados = 0
        self.bytes_recebidos = 0
        self.mensagens_enviadas = 0
        self.mensagens_recebidas = 0
        self.mensagens_erro = 0
        self.conexoes_estabelecidas = 0
        
        # Timestamps
        self.inicio_monitor = time.time()
        self.inicio_conexao_atual = None
        self.ultima_atividade = time.time()
        
        # Histórico para throughput
        self.historico_bytes_enviados = deque(maxlen=60)
        self.historico_bytes_recebidos = deque(maxlen=60)
        self.historico_timestamps = deque(maxlen=60)
        
        # Latência
        self.latencias = deque(maxlen=100)
        self.pendentes_ping = {}
        
        # Estado da conexão
        self.socket_ativo = None
        self.endereco_remoto = None
        self.porta_local = None
        self.porta_remota = None
        self.estado_conexao = "Desligado"
        
        # Thread para coleta contínua
        self.a_monitorizar = True
        self.thread_monitor = threading.Thread(target=self.coleta_continua, daemon=True)
        self.thread_monitor.start()
        
        print(f"Monitor TCP inicializado para {nome_componente}")
    
    def definir_socket_ativo(self, socket_tcp, endereco_remoto=None):
        self.socket_ativo = socket_tcp
        self.endereco_remoto = endereco_remoto
        self.inicio_conexao_atual = time.time()
        self.estado_conexao = "Conectado"
        self.conexoes_estabelecidas += 1
        
        if socket_tcp:
            try:
                endereco_local = socket_tcp.getsockname()
                self.porta_local = endereco_local[1]
                
                if endereco_remoto:
                    self.porta_remota = endereco_remoto[1] if isinstance(endereco_remoto, tuple) else None
                
                print(f"Monitor TCP: Conexão estabelecida {endereco_local} <-> {endereco_remoto}")
                
            except Exception as e:
                print(f"Erro ao obter informações do socket: {e}")
    
    def conexao_perdida(self):
        self.socket_ativo = None
        self.estado_conexao = "Desligado"
        self.endereco_remoto = None
        print(f"Monitor TCP: Conexão perdida")
    
    def registrar_envio(self, tamanho_bytes, sucesso=True):
        if sucesso:
            self.bytes_enviados += tamanho_bytes
            self.mensagens_enviadas += 1
        else:
            self.mensagens_erro += 1
        
        self.ultima_atividade = time.time()
    
    def registrar_recepcao(self, tamanho_bytes, sucesso=True):
        if sucesso:
            self.bytes_recebidos += tamanho_bytes
            self.mensagens_recebidas += 1
        else:
            self.mensagens_erro += 1
        
        self.ultima_atividade = time.time()
    
    def iniciar_medicao_latencia(self, id_ping):
        self.pendentes_ping[id_ping] = time.time()
    
    def finalizar_medicao_latencia(self, id_ping):
        if id_ping in self.pendentes_ping:
            inicio = self.pendentes_ping.pop(id_ping)
            latencia_ms = (time.time() - inicio) * 1000
            self.latencias.append(latencia_ms)
            return latencia_ms
        return None
    
    def obter_throughput(self):
        agora = time.time()
        
        # Remove entradas antigas
        while (self.historico_timestamps and 
               agora - self.historico_timestamps[0] > 60):
            self.historico_timestamps.popleft()
            if self.historico_bytes_enviados:
                self.historico_bytes_enviados.popleft()
            if self.historico_bytes_recebidos:
                self.historico_bytes_recebidos.popleft()
        
        if len(self.historico_timestamps) < 2:
            return 0.0, 0.0
        
        tempo_decorrido = self.historico_timestamps[-1] - self.historico_timestamps[0]
        if tempo_decorrido <= 0:
            return 0.0, 0.0
        
        bytes_enviados_periodo = sum(self.historico_bytes_enviados)
        bytes_recebidos_periodo = sum(self.historico_bytes_recebidos)
        
        throughput_envio = bytes_enviados_periodo / tempo_decorrido
        throughput_recepcao = bytes_recebidos_periodo / tempo_decorrido
        
        return throughput_envio, throughput_recepcao
    
    def obter_latencia_media(self):
        if not self.latencias:
            return 0.0
        
        return sum(self.latencias) / len(self.latencias)
    
    def obter_parametros_socket(self):
        parametros = {
            'window_size': None,
            'buffer_size_envio': None,
            'buffer_size_recepcao': None,
            'keepalive': None,
            'nodelay': None,
            'timeout': None
        }
        
        if not self.socket_ativo:
            return parametros
        
        try:
            parametros['buffer_size_recepcao'] = self.socket_ativo.getsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF
            )
            
            parametros['buffer_size_envio'] = self.socket_ativo.getsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF
            )
            
            parametros['keepalive'] = bool(self.socket_ativo.getsockopt(
                socket.SOL_SOCKET, socket.SO_KEEPALIVE
            ))
            
            parametros['nodelay'] = bool(self.socket_ativo.getsockopt(
                socket.IPPROTO_TCP, socket.TCP_NODELAY
            ))
            
            parametros['timeout'] = self.socket_ativo.gettimeout()
            parametros['window_size'] = parametros['buffer_size_recepcao']
            
        except Exception as e:
            print(f"Erro ao obter parâmetros do socket: {e}")
        
        return parametros
    
    def obter_estatisticas_conexao(self):
        agora = time.time()
        tempo_ativo = agora - self.inicio_monitor
        tempo_conexao = agora - self.inicio_conexao_atual if self.inicio_conexao_atual else 0
        
        throughput_envio, throughput_recepcao = self.obter_throughput()
        latencia_media = self.obter_latencia_media()
        parametros_socket = self.obter_parametros_socket()
        
        total_mensagens = self.mensagens_enviadas + self.mensagens_recebidas
        taxa_sucesso = 0.0
        if total_mensagens > 0:
            taxa_sucesso = ((total_mensagens - self.mensagens_erro) / total_mensagens) * 100
        
        estatisticas = {
            'componente': self.nome_componente,
            'estado_ligacao': self.estado_conexao,
            'tempo_ativo_total': tempo_ativo,
            'tempo_conexao_atual': tempo_conexao,
            'endereco_local': f"localhost:{self.porta_local}" if self.porta_local else "N/A",
            'endereco_remoto': f"{self.endereco_remoto[0]}:{self.endereco_remoto[1]}" if self.endereco_remoto else "N/A",
            
            'bytes_enviados': self.bytes_enviados,
            'bytes_recebidos': self.bytes_recebidos,
            'mensagens_enviadas': self.mensagens_enviadas,
            'mensagens_recebidas': self.mensagens_recebidas,
            'mensagens_erro': self.mensagens_erro,
            'conexoes_estabelecidas': self.conexoes_estabelecidas,
            
            'throughput_envio_bps': throughput_envio,
            'throughput_recepcao_bps': throughput_recepcao,
            'latencia_media_ms': latencia_media,
            'taxa_sucesso_percent': taxa_sucesso,
            
            'parametros_tcp': parametros_socket,
            
            'ultima_atividade': self.ultima_atividade,
            'inicio_monitor': self.inicio_monitor
        }
        
        return estatisticas
    
    def coleta_continua(self):
        ultimo_bytes_enviados = 0
        ultimo_bytes_recebidos = 0
        
        while self.a_monitorizar:
            try:
                agora = time.time()
                
                bytes_enviados_delta = self.bytes_enviados - ultimo_bytes_enviados
                bytes_recebidos_delta = self.bytes_recebidos - ultimo_bytes_recebidos
                
                self.historico_timestamps.append(agora)
                self.historico_bytes_enviados.append(bytes_enviados_delta)
                self.historico_bytes_recebidos.append(bytes_recebidos_delta)
                
                ultimo_bytes_enviados = self.bytes_enviados
                ultimo_bytes_recebidos = self.bytes_recebidos
                
                if self.socket_ativo:
                    try:
                        self.socket_ativo.setblocking(False)
                        try:
                            self.socket_ativo.recv(0)
                        except socket.error:
                            pass
                        finally:
                            self.socket_ativo.setblocking(True)
                    except:
                        self.conexao_perdida()
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Erro na coleta contínua: {e}")
                time.sleep(1)
    
    def formatar_bytes(self, bytes_valor):
        if bytes_valor < 1024:
            return f"{bytes_valor} B"
        elif bytes_valor < 1024 * 1024:
            return f"{bytes_valor / 1024:.1f} KB"
        elif bytes_valor < 1024 * 1024 * 1024:
            return f"{bytes_valor / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_valor / (1024 * 1024 * 1024):.1f} GB"
    
    def formatar_tempo(self, segundos):
        if segundos < 60:
            return f"{segundos:.0f}s"
        elif segundos < 3600:
            minutos = int(segundos // 60)
            segundos_rest = int(segundos % 60)
            return f"{minutos:02d}:{segundos_rest:02d}"
        else:
            horas = int(segundos // 3600)
            minutos = int((segundos % 3600) // 60)
            segundos_rest = int(segundos % 60)
            return f"{horas:02d}:{minutos:02d}:{segundos_rest:02d}"
    
    def gerar_relatorio_detalhado(self):
        stats = self.obter_estatisticas_conexao()
        
        relatorio = []
        relatorio.append("=" * 60)
        relatorio.append(f"PARÂMETROS TCP - {stats['componente'].upper()}")
        relatorio.append("=" * 60)
        
        relatorio.append("INFORMAÇÕES DA CONEXÃO:")
        relatorio.append(f"  Estado: {stats['estado_ligacao']}")
        relatorio.append(f"  Endereço local: {stats['endereco_local']}")
        relatorio.append(f"  Endereço remoto: {stats['endereco_remoto']}")
        relatorio.append(f"  Tempo ativo: {self.formatar_tempo(stats['tempo_ativo_total'])}")
        if stats['tempo_conexao_atual'] > 0:
            relatorio.append(f"  Conexão atual: {self.formatar_tempo(stats['tempo_conexao_atual'])}")
        relatorio.append("")
        
        relatorio.append("ESTATÍSTICAS DE TRÁFEGO:")
        relatorio.append(f"  Bytes enviados: {self.formatar_bytes(stats['bytes_enviados'])}")
        relatorio.append(f"  Bytes recebidos: {self.formatar_bytes(stats['bytes_recebidos'])}")
        relatorio.append(f"  Mensagens enviadas: {stats['mensagens_enviadas']}")
        relatorio.append(f"  Mensagens recebidas: {stats['mensagens_recebidas']}")
        relatorio.append(f"  Mensagens com erro: {stats['mensagens_erro']}")
        relatorio.append(f"  Conexões estabelecidas: {stats['conexoes_estabelecidas']}")
        relatorio.append("")
        
        relatorio.append("MÉTRICAS DE PERFORMANCE:")
        relatorio.append(f"  Throughput envio: {self.formatar_bytes(stats['throughput_envio_bps'])}/s")
        relatorio.append(f"  Throughput recepção: {self.formatar_bytes(stats['throughput_recepcao_bps'])}/s")
        relatorio.append(f"  Latência média: {stats['latencia_media_ms']:.1f} ms")
        relatorio.append(f"  Taxa de sucesso: {stats['taxa_sucesso_percent']:.1f}%")
        relatorio.append("")
        
        relatorio.append("PARÂMETROS TCP:")
        tcp_params = stats['parametros_tcp']
        if tcp_params['window_size']:
            relatorio.append(f"  Window Size: {self.formatar_bytes(tcp_params['window_size'])}")
        if tcp_params['buffer_size_envio']:
            relatorio.append(f"  Buffer envio: {self.formatar_bytes(tcp_params['buffer_size_envio'])}")
        if tcp_params['buffer_size_recepcao']:
            relatorio.append(f"  Buffer recepção: {self.formatar_bytes(tcp_params['buffer_size_recepcao'])}")
        if tcp_params['keepalive'] is not None:
            relatorio.append(f"  Keep Alive: {'Ativo' if tcp_params['keepalive'] else 'Inativo'}")
        if tcp_params['nodelay'] is not None:
            relatorio.append(f"  TCP No Delay: {'Ativo' if tcp_params['nodelay'] else 'Inativo'}")
        if tcp_params['timeout']:
            relatorio.append(f"  Timeout: {tcp_params['timeout']:.1f}s")
        
        relatorio.append("=" * 60)
        
        return "\n".join(relatorio)
    
    def parar(self):
        self.a_monitorizar = False
        print(f"Monitor TCP parado para {self.nome_componente}")

def testar_monitor():
    print("Testando Monitor TCP...")
    
    monitor = MonitorTCP("Teste")
    
    monitor.registrar_envio(100)
    monitor.registrar_recepcao(80)
    monitor.registrar_envio(200)
    monitor.registrar_recepcao(150)
    
    monitor.iniciar_medicao_latencia("ping1")
    time.sleep(0.001)
    monitor.finalizar_medicao_latencia("ping1")
    
    time.sleep(2)
    
    print(monitor.gerar_relatorio_detalhado())
    
    monitor.parar()

if __name__ == "__main__":
    testar_monitor()