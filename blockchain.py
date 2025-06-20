from dataclasses import dataclass
from typing import Optional
import time
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
        data = f"1.0{previous_hash}{time.time()}{transactions}"
        block_hash = str(simple_hash(data, 1000))
        
        # Criar novo bloco
        new_block = Block(
            version="1.0",
            previous_hash=previous_hash,
            timestamp=time.time(),
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
        print(f"Bloco adicionado: {transactions}")
    
    def mostrar_blockchain(self):
        """Mostra todos os blocos"""
        current = self.head
        i = 0
        while current:
            print(f"\nBloco {i}:")
            print(f"  Hash: {current.hash}")
            print(f"  Transações: {current.transactions}")
            current = current.next_block
            i += 1


# Teste simples
blockchain = SimpleBlockchain()
blockchain.add_block("Alice envia 10 para Bob")
blockchain.add_block("Bob envia 5 para Charlie")
blockchain.mostrar_blockchain()