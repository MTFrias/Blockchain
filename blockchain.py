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

    
    
    def __post_init__(self):
        """Calcula o hash do bloco após a inicialização se não foi fornecido"""
        if not self.hash:
            self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calcula o hash do bloco baseado nos seus dados"""
        # Concatena todos os dados do bloco para criar o hash
        data = f"{self.version}{self.previous_hash}{self.timestamp}{self.transactions}"
        # Usa a função de hash do arquivo criptografiaBase
        hash_value = simple_hash(data, 1000000)  # Usando um bucket grande para mais variabilidade
        return str(hash_value)
    
    def is_valid(self) -> bool:
        """Verifica se o hash do bloco é válido"""
        return self.hash == self.calculate_hash()


class SimpleBlockchain:
    def __init__(self):
        self.head: Optional[Block] = None  # Primeiro bloco (Genesis)
        self.tail: Optional[Block] = None  # Último bloco
        self.size: int = 0
        
        # Criar o bloco gênesis automaticamente
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Cria o primeiro bloco da blockchain (Genesis Block)"""
        genesis_block = Block(
            version="1.0",
            previous_hash="0",  # Genesis block não tem anterior
            timestamp=time.time(),
            hash="",  # Será calculado automaticamente
            transactions="Genesis Block - Blockchain Iniciada"
        )
        
        self.head = genesis_block
        self.tail = genesis_block
        self.size = 1
        
        print(f"🎯 Bloco Gênesis criado com hash: {genesis_block.hash}")
    
    def add_block(self, transactions: str, version: str = "1.0") -> Block:
        """Adiciona um novo bloco ao final da blockchain"""
        if not self.tail:
            raise Exception("Blockchain não inicializada!")
        
        # Criar novo bloco
        new_block = Block(
            version=version,
            previous_hash=self.tail.hash,  # Hash do último bloco
            timestamp=time.time(),
            hash="",  # Será calculado automaticamente
            transactions=transactions
        )
        
        # Conectar na lista duplamente ligada
        new_block.previous_block = self.tail
        self.tail.next_block = new_block
        self.tail = new_block
        self.size += 1
        
        print(f"✅ Novo bloco adicionado com hash: {new_block.hash}")
        return new_block
    
    def get_block_by_index(self, index: int) -> Optional[Block]:
        """Retorna o bloco na posição especificada"""
        if index < 0 or index >= self.size:
            return None
        
        current = self.head
        for i in range(index):
            current = current.next_block
        
        return current
    
    def get_block_by_hash(self, hash_value: str) -> Optional[Block]:
        """Encontra um bloco pelo seu hash"""
        current = self.head
        while current:
            if current.hash == hash_value:
                return current
            current = current.next_block
        return None
    
    def validate_chain(self) -> bool:
        """Valida toda a blockchain"""
        print("\n🔍 Validando blockchain...")
        
        current = self.head
        while current:
            # Verificar se o hash do bloco é válido
            if not current.is_valid():
                print(f"❌ Bloco com hash {current.hash} tem hash inválido!")
                return False
            
            # Verificar se o previous_hash está correto (exceto para o genesis)
            if current.previous_block:
                if current.previous_hash != current.previous_block.hash:
                    print(f"❌ Bloco com hash {current.hash} tem previous_hash incorreto!")
                    return False
            
            current = current.next_block
        
        print("✅ Blockchain válida!")
        return True
    
    def display_chain(self):
        """Exibe toda a blockchain de forma formatada"""
        print(f"\n📊 === BLOCKCHAIN ({self.size} blocos) ===")
        
        current = self.head
        index = 0
        
        while current:
            print(f"\n🔗 BLOCO {index}")
            print(f"   Versão: {current.version}")
            print(f"   Hash: {current.hash}")
            print(f"   Hash Anterior: {current.previous_hash}")
            print(f"   Timestamp: {current.timestamp}")
            print(f"   Transações: {current.transactions}")
            print(f"   Válido: {'✅' if current.is_valid() else '❌'}")
            
            current = current.next_block
            index += 1
    
    def display_chain_reverse(self):
        """Exibe a blockchain de trás para frente (usando a lista duplamente ligada)"""
        print(f"\n📊 === BLOCKCHAIN REVERSA ({self.size} blocos) ===")
        
        current = self.tail
        index = self.size - 1
        
        while current:
            print(f"\n🔗 BLOCO {index}")
            print(f"   Hash: {current.hash}")
            print(f"   Transações: {current.transactions}")
            
            current = current.previous_block
            index -= 1
    
    def get_chain_info(self) -> dict:
        """Retorna informações gerais da blockchain"""
        return {
            "total_blocks": self.size,
            "genesis_hash": self.head.hash if self.head else None,
            "latest_hash": self.tail.hash if self.tail else None,
            "is_valid": self.validate_chain()
        }


# === EXEMPLO DE USO ===
def demo_blockchain():
    print("🚀 Demonstração do Blockchain Simples")
    print("=" * 50)
    
    # Criar blockchain
    blockchain = SimpleBlockchain()
    
    # Adicionar alguns blocos
    blockchain.add_block("Alice envia 10 moedas para Bob")
    blockchain.add_block("Bob envia 5 moedas para Charlie")
    blockchain.add_block("Charlie envia 3 moedas para Diana")
    blockchain.add_block("Diana envia 1 moeda para Alice")
    
    # Exibir a blockchain
    blockchain.display_chain()
    
    # Validar a blockchain
    blockchain.validate_chain()
    
    # Exibir informações gerais
    info = blockchain.get_chain_info()
    print(f"\n📈 Informações da Blockchain:")
    print(f"   Total de blocos: {info['total_blocks']}")
    print(f"   Hash do Genesis: {info['genesis_hash']}")
    print(f"   Hash do último bloco: {info['latest_hash']}")
    print(f"   Blockchain válida: {info['is_valid']}")
    
    # Demonstrar navegação reversa
    print("\n🔄 Navegação reversa:")
    blockchain.display_chain_reverse()
    
    # Buscar bloco por index
    print(f"\n🔍 Bloco na posição 2: {blockchain.get_block_by_index(2).transactions}")
    
    # Tentar modificar um bloco (vai invalidar a chain)
    print(f"\n🛠️ Tentando modificar um bloco...")
    second_block = blockchain.get_block_by_index(1)
    if second_block:
        second_block.transactions = "Transação MODIFICADA ILEGALMENTE!"
        print(f"   Blockchain ainda válida? {blockchain.validate_chain()}")


if __name__ == "__main__":
    demo_blockchain()
