from dataclasses import dataclass
from typing import Optional
import time
from datetime import datetime
from criptografiaBase import simple_hash


@dataclass
class Block:
    version: str
    previous_hash: str
    timestamp: float
    hash: str
    transactions: str
    next_block: Optional['Block'] = None
    previous_block: Optional['Block'] = None


class SimpleBlockchain:
    def __init__(self):
        self.head: Optional[Block] = None  # Primeiro bloco
        self.tail: Optional[Block] = None  # Último bloco
        self.size: int = 0
    
    def add_block(self, transactions: str):
        """Adiciona um novo bloco"""
        # Se é o primeiro bloco
        if self.head is None:
            previous_hash = "0"
        else:
            previous_hash = self.tail.hash
        
        # Calcular hash do novo bloco
        current_timestamp = time.time() # Usar o mesmo timestamp para o hash e para o bloco
        data = f"1.0{previous_hash}{current_timestamp}{transactions}"
        block_hash = str(simple_hash(data, 1000))
        
        # Criar novo bloco
        new_block = Block(
            version="1.0",
            previous_hash=previous_hash,
            timestamp=current_timestamp,
            hash=block_hash,
            transactions=transactions
        )
        
        # Se é o primeiro bloco
        if self.head is None:
            self.head = new_block
            self.tail = new_block
        else:
            # Ligar à lista
            self.tail.next_block = new_block
            new_block.previous_block = self.tail
            self.tail = new_block
        
        self.size += 1
        # A mensagem no gestor já é suficiente, podemos remover esta para não poluir o output
        # print(f"Bloco adicionado: {transactions}")
    
    def mostrar_blockchain(self):
        """Mostra todos os detalhes de cada bloco na blockchain."""
        current = self.head
        i = 0
        
        if not current:
            print("A blockchain está vazia.")
            return

        while current:
            # Converte o timestamp para um formato de data e hora legível
            ts = datetime.fromtimestamp(current.timestamp).strftime('%Y-%m-%d %H:%M:%S')

            print(f"Bloco {i}:")
            print(f"  Versão: {current.version}")
            print(f"  Timestamp: {ts}")
            print(f"  Transações: {current.transactions}")
            print(f"  Hash: {current.hash}")
            print(f"  Hash Anterior: {current.previous_hash}")
            # Adiciona uma linha para separar visualmente os blocos
            print("-" * 40) 
            
            current = current.next_block
            i += 1

'''
if __name__ == "__main__":
    from datetime import datetime # Importar datetime para o teste
    
    blockchain = SimpleBlockchain()
    blockchain.add_block("Alice envia 10 para Bob")
    time.sleep(1) # Pequena pausa para ter timestamps diferentes
    blockchain.add_block("Bob envia 5 para Charlie")
    
    print("\n--- ESTADO FINAL DA BLOCKCHAIN ---")
    blockchain.mostrar_blockchain()
    print(f"Tamanho total: {blockchain.size} blocos")
'''