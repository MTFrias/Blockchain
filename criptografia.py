#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
criptografia.py - Sistema de criptografia multi-algoritmo corrigido
CORREÇÃO: Parâmetros Diffie-Hellman fixos e idênticos
"""

import hashlib
import hmac
import secrets
import time
import os

# PARÂMETROS DIFFIE-HELLMAN FIXOS (idênticos para cliente e servidor)
DH_PRIME = 2**31 - 1  # Primo de Mersenne
DH_GENERATOR = 2      # Gerador fixo

class DiffieHellman:
    """
    Implementação Diffie-Hellman com parâmetros fixos
    """
    
    def __init__(self):
        # Usa sempre os mesmos parâmetros
        self.prime = DH_PRIME
        self.generator = DH_GENERATOR
        self.private_key = secrets.randbelow(self.prime - 2) + 1
        self.public_key = pow(self.generator, self.private_key, self.prime)
        self.shared_key = None
    
    def obter_chave_publica(self):
        return self.public_key
    
    def calcular_chave_partilhada(self, chave_publica_remota):
        self.shared_key = pow(chave_publica_remota, self.private_key, self.prime)
        return self.shared_key
    
    def obter_chave_partilhada(self):
        return self.shared_key

class FuncaoHash:
    """
    Funções de hash para integridade
    """
    
    @staticmethod
    def sha256(dados):
        return hashlib.sha256(dados.encode('utf-8')).hexdigest()
    
    @staticmethod
    def verificar_integridade(dados, hash_esperado, algoritmo='sha256'):
        if algoritmo == 'sha256':
            hash_calculado = FuncaoHash.sha256(dados)
            return hash_calculado == hash_esperado
        return False

class FuncaoHMAC:
    """
    Funções HMAC para autenticação
    """
    
    @staticmethod
    def calcular_hmac(dados, chave, algoritmo='sha256'):
        chave_bytes = str(chave).encode('utf-8')
        dados_bytes = dados.encode('utf-8')
        return hmac.new(chave_bytes, dados_bytes, hashlib.sha256).hexdigest()
    
    @staticmethod
    def verificar_hmac(dados, chave, hmac_esperado, algoritmo='sha256'):
        hmac_calculado = FuncaoHMAC.calcular_hmac(dados, chave, algoritmo)
        return hmac_calculado == hmac_esperado

class CifraCesar:
    """
    Cifra de César generalizada com deslocamento dinâmico
    """
    
    def __init__(self, chave_base):
        self.chave_base = chave_base % 95
        self.caracteres = ''.join(chr(i) for i in range(32, 127))  # 95 caracteres ASCII
    
    def cifrar(self, texto):
        resultado = ""
        for char in texto:
            if char in self.caracteres:
                pos_original = self.caracteres.index(char)
                nova_pos = (pos_original + self.chave_base) % 95
                resultado += self.caracteres[nova_pos]
            else:
                resultado += char
        return resultado
    
    def decifrar(self, texto_cifrado):
        resultado = ""
        for char in texto_cifrado:
            if char in self.caracteres:
                pos_cifrada = self.caracteres.index(char)
                pos_original = (pos_cifrada - self.chave_base) % 95
                resultado += self.caracteres[pos_original]
            else:
                resultado += char
        return resultado
    
    def cifrar_com_nonce(self, texto):
        nonce = secrets.randbelow(1000000000)
        chave_dinamica = (self.chave_base + nonce) % 95
        
        resultado = ""
        for char in texto:
            if char in self.caracteres:
                pos_original = self.caracteres.index(char)
                nova_pos = (pos_original + chave_dinamica) % 95
                resultado += self.caracteres[nova_pos]
            else:
                resultado += char
        
        return resultado, nonce
    
    def decifrar_com_nonce(self, texto_cifrado, nonce):
        chave_dinamica = (self.chave_base + nonce) % 95
        
        resultado = ""
        for char in texto_cifrado:
            if char in self.caracteres:
                pos_cifrada = self.caracteres.index(char)
                pos_original = (pos_cifrada - chave_dinamica) % 95
                resultado += self.caracteres[pos_original]
            else:
                resultado += char
        return resultado

class CifraVigenere:
    """
    Cifra de Vigenère generalizada com deslocamento dinâmico
    """
    
    def __init__(self, chave_base):
        self.chave_base = str(chave_base)
        self.caracteres = ''.join(chr(i) for i in range(32, 127))
    
    def preparar_chave(self, texto, nonce=None):
        chave = self.chave_base
        if nonce is not None:
            chave = chave + str(nonce)
        
        while len(chave) < len(texto):
            chave += chave
        return chave[:len(texto)]
    
    def cifrar(self, texto):
        chave_expandida = self.preparar_chave(texto)
        resultado = ""
        
        for i, char in enumerate(texto):
            if char in self.caracteres:
                pos_char = self.caracteres.index(char)
                pos_chave = self.caracteres.index(chave_expandida[i] if chave_expandida[i] in self.caracteres else self.caracteres[0])
                nova_pos = (pos_char + pos_chave) % 95
                resultado += self.caracteres[nova_pos]
            else:
                resultado += char
        
        return resultado
    
    def decifrar(self, texto_cifrado):
        chave_expandida = self.preparar_chave(texto_cifrado)
        resultado = ""
        
        for i, char in enumerate(texto_cifrado):
            if char in self.caracteres:
                pos_char = self.caracteres.index(char)
                pos_chave = self.caracteres.index(chave_expandida[i] if chave_expandida[i] in self.caracteres else self.caracteres[0])
                pos_original = (pos_char - pos_chave) % 95
                resultado += self.caracteres[pos_original]
            else:
                resultado += char
        
        return resultado
    
    def cifrar_com_nonce(self, texto):
        nonce = secrets.randbelow(1000000000)
        chave_expandida = self.preparar_chave(texto, nonce)
        resultado = ""
        
        for i, char in enumerate(texto):
            if char in self.caracteres:
                pos_char = self.caracteres.index(char)
                pos_chave = self.caracteres.index(chave_expandida[i] if chave_expandida[i] in self.caracteres else self.caracteres[0])
                nova_pos = (pos_char + pos_chave) % 95
                resultado += self.caracteres[nova_pos]
            else:
                resultado += char
        
        return resultado, nonce
    
    def decifrar_com_nonce(self, texto_cifrado, nonce):
        chave_expandida = self.preparar_chave(texto_cifrado, nonce)
        resultado = ""
        
        for i, char in enumerate(texto_cifrado):
            if char in self.caracteres:
                pos_char = self.caracteres.index(char)
                pos_chave = self.caracteres.index(chave_expandida[i] if chave_expandida[i] in self.caracteres else self.caracteres[0])
                pos_original = (pos_char - pos_chave) % 95
                resultado += self.caracteres[pos_original]
            else:
                resultado += char
        
        return resultado

class GestorCriptografia:
    """
    Gestor principal de criptografia
    """
    
    def __init__(self):
        self.diffie_hellman = None
        self.chave_estabelecida = False
        self.chave_hmac = None
        
        self.cifra_cesar = None
        self.cifra_vigenere = None
        
        self.algoritmo_ativo = 'cesar'
        self.algoritmos_disponiveis = ['cesar', 'vigenere']
        self.algoritmo_hash = 'sha256'
        self.usar_hmac = True
        self.usar_deslocamento_dinamico = True
        
        # Cria pasta de debug se não existir
        os.makedirs("debug_cripto", exist_ok=True)
    
    def inicializar_diffie_hellman(self):
        self.diffie_hellman = DiffieHellman()
        return self.diffie_hellman.obter_chave_publica()
    
    def finalizar_diffie_hellman(self, chave_publica_remota):
        if not self.diffie_hellman:
            return False
        
        chave_partilhada = self.diffie_hellman.calcular_chave_partilhada(chave_publica_remota)
        
        # Deriva chaves dos algoritmos a partir da chave partilhada
        chave_cesar = int(str(chave_partilhada)[:6]) % 95
        chave_vigenere = str(chave_partilhada)[:20]
        
        self.cifra_cesar = CifraCesar(chave_cesar)
        self.cifra_vigenere = CifraVigenere(chave_vigenere)
        
        # Chave HMAC
        self.chave_hmac = str(chave_partilhada)[-20:]
        
        self.chave_estabelecida = True
        return True
    
    def alterar_algoritmo(self, algoritmo):
        if algoritmo.lower() in self.algoritmos_disponiveis:
            self.algoritmo_ativo = algoritmo.lower()
            return True
        return False
    
    def cifrar_mensagem(self, mensagem):
        if not self.chave_estabelecida:
            raise ValueError("Chave criptográfica não foi estabelecida")
        
        # Debug
        with open("debug_cripto/debug_cripto.txt", "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] Cifrando com {self.algoritmo_ativo.upper()}: '{mensagem}'\n")
        
        if self.algoritmo_ativo == 'cesar':
            if self.usar_deslocamento_dinamico:
                mensagem_cifrada, nonce = self.cifra_cesar.cifrar_com_nonce(mensagem)
                with open("debug_cripto/debug_cripto.txt", "a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] CESAR: Nonce gerado: {nonce}\n")
            else:
                mensagem_cifrada = self.cifra_cesar.cifrar(mensagem)
                nonce = None
        
        elif self.algoritmo_ativo == 'vigenere':
            if self.usar_deslocamento_dinamico:
                mensagem_cifrada, nonce = self.cifra_vigenere.cifrar_com_nonce(mensagem)
                with open("debug_cripto/debug_cripto.txt", "a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] VIGENERE: Nonce gerado: {nonce}\n")
                    f.write(f"[{time.strftime('%H:%M:%S')}] VIGENERE: Chave dinâmica: '{self.cifra_vigenere.preparar_chave(mensagem, nonce)[:20]}...' para texto: {mensagem}\n")
            else:
                mensagem_cifrada = self.cifra_vigenere.cifrar(mensagem)
                nonce = None
        
        # Hash para integridade
        hash_integridade = FuncaoHash.sha256(mensagem)
        
        # HMAC para autenticação
        hmac_autenticacao = None
        if self.usar_hmac and self.chave_hmac:
            hmac_autenticacao = FuncaoHMAC.calcular_hmac(mensagem, self.chave_hmac, self.algoritmo_hash)
        
        return mensagem_cifrada, hash_integridade, nonce, self.algoritmo_ativo, hmac_autenticacao
    
    def decifrar_mensagem(self, mensagem_cifrada, hash_esperado, nonce=None, algoritmo=None, hmac_esperado=None):
        if not self.chave_estabelecida:
            raise ValueError("Chave criptográfica não foi estabelecida")
        
        if algoritmo is None:
            algoritmo = self.algoritmo_ativo
        
        # Debug
        with open("debug_cripto/debug_cripto.txt", "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] Decifrando com {algoritmo.upper()}: '{mensagem_cifrada}' nonce: {nonce}\n")
        
        if algoritmo == 'cesar':
            if nonce is not None and self.usar_deslocamento_dinamico:
                mensagem_decifrada = self.cifra_cesar.decifrar_com_nonce(mensagem_cifrada, nonce)
            else:
                mensagem_decifrada = self.cifra_cesar.decifrar(mensagem_cifrada)
        
        elif algoritmo == 'vigenere':
            if nonce is not None and self.usar_deslocamento_dinamico:
                mensagem_decifrada = self.cifra_vigenere.decifrar_com_nonce(mensagem_cifrada, nonce)
            else:
                mensagem_decifrada = self.cifra_vigenere.decifrar(mensagem_cifrada)
        
        # Verifica integridade
        integridade_ok = FuncaoHash.verificar_integridade(
            mensagem_decifrada, hash_esperado, self.algoritmo_hash
        )
        
        # Verifica autenticação
        autenticacao_ok = True
        if hmac_esperado and self.usar_hmac and self.chave_hmac:
            autenticacao_ok = FuncaoHMAC.verificar_hmac(
                mensagem_decifrada, self.chave_hmac, hmac_esperado, self.algoritmo_hash
            )
        
        return mensagem_decifrada, integridade_ok, autenticacao_ok
    
    def obter_estado(self):
        estado = {
            'chave_estabelecida': self.chave_estabelecida,
            'algoritmo_ativo': self.algoritmo_ativo,
            'algoritmos_disponiveis': self.algoritmos_disponiveis,
            'algoritmo_hash': self.algoritmo_hash,
            'usar_hmac': self.usar_hmac,
            'deslocamento_dinamico': self.usar_deslocamento_dinamico,
            'chave_publica_dh': None,
            'chave_partilhada_dh': None,
            'chave_base_cesar': None,
            'chave_base_vigenere': None
        }
        
        if self.diffie_hellman:
            estado['chave_publica_dh'] = self.diffie_hellman.obter_chave_publica()
            estado['chave_partilhada_dh'] = self.diffie_hellman.obter_chave_partilhada()
        
        if self.cifra_cesar:
            estado['chave_base_cesar'] = self.cifra_cesar.chave_base
        
        if self.cifra_vigenere:
            estado['chave_base_vigenere'] = self.cifra_vigenere.chave_base[:10] + "..."
        
        return estado

def testar_criptografia():
    """
    Teste básico do sistema
    """
    print("Testando sistema de criptografia...")
    
    # Teste Diffie-Hellman
    dh1 = DiffieHellman()
    dh2 = DiffieHellman()
    
    chave_pub1 = dh1.obter_chave_publica()
    chave_pub2 = dh2.obter_chave_publica()
    
    chave_part1 = dh1.calcular_chave_partilhada(chave_pub2)
    chave_part2 = dh2.calcular_chave_partilhada(chave_pub1)
    
    if chave_part1 == chave_part2:
        print("✓ Diffie-Hellman OK")
    else:
        print("✗ Diffie-Hellman FALHOU")
        return False
    
    # Teste gestores
    gestor1 = GestorCriptografia()
    gestor2 = GestorCriptografia()
    
    chave_pub_cliente = gestor1.inicializar_diffie_hellman()
    chave_pub_servidor = gestor2.inicializar_diffie_hellman()
    
    gestor1.finalizar_diffie_hellman(chave_pub_servidor)
    gestor2.finalizar_diffie_hellman(chave_pub_cliente)
    
    mensagem = "Teste de criptografia"
    
    for algoritmo in ['cesar', 'vigenere']:
        gestor1.alterar_algoritmo(algoritmo)
        gestor2.alterar_algoritmo(algoritmo)
        
        msg_cifrada, hash_msg, nonce, alg, hmac_msg = gestor1.cifrar_mensagem(mensagem)
        msg_decifrada, integridade, autenticacao = gestor2.decifrar_mensagem(
            msg_cifrada, hash_msg, nonce, alg, hmac_msg
        )
        
        if msg_decifrada == mensagem and integridade and autenticacao:
            print(f"✓ {algoritmo.upper()} OK")
        else:
            print(f"✗ {algoritmo.upper()} FALHOU")
            return False
    
    print("✓ Todos os testes passaram")
    return True

if __name__ == "__main__":
    testar_criptografia()