# Importações. Coisas que vamos precisar para a nossa geringonça funcionar.
from dataclasses import dataclass # Para criar classes de dados de forma fácil.
from typing import Optional # Para dizer que uma variável pode ser "nada" (None).
import time # Para trabalhar com tempo, tipo timestamps.
from datetime import datetime # Para formatar as datas e horas de forma legível.
from criptografiaBase import simple_hash # A nossa função para criar hashes.


@dataclass
# A "receita" para fazer um bloco. Define a estrutura de cada bloco da corrente.
class Block:
    version: str # Versão do bloco (ex: "1.0").
    previous_hash: str # O hash do bloco anterior, para criar a ligação.
    timestamp: float # Quando o bloco foi criado.
    hash: str # O hash deste próprio bloco. A sua "impressão digital".
    transactions: str # Os dados/transações que o bloco guarda (ex: "Zé enviou 5€ à Maria").
    next_block: Optional['Block'] = None # Aponta para o bloco seguinte.
    previous_block: Optional['Block'] = None # Aponta para o bloco anterior.


# O cérebro da nossa blockchain. Gere a corrente de blocos.
class SimpleBlockchain:
    # O construtor. Quando criamos uma blockchain, ela começa assim:
    def __init__(self):
        self.head: Optional[Block] = None  # O primeiro bloco da corrente (a "cabeça").
        self.tail: Optional[Block] = None  # O último bloco da corrente (a "cauda").
        self.size: int = 0 # Quantos blocos já temos.

    # Método para meter um novo bloco na corrente.
    def add_block(self, transactions: str):
        """Adiciona um novo bloco"""

        # Se for o primeiro bloco (génese), o hash anterior é "0".
        if self.head is None:
            previous_hash = "0"
        # Senão, vai buscar o hash do último bloco que já existe.
        else:
            previous_hash = self.tail.hash

        current_timestamp = time.time() # Pega na hora e data exatas de agora.
        
         # Junta os dados todos numa string só para calcular o hash.
        data = f"1.0{previous_hash}{current_timestamp}{transactions}"
      
        # "Cozinha" o hash do novo bloco a partir dos dados.
        block_hash = str(simple_hash(data, 1000))

        # Cria o novo bloco com a informação toda.
        new_block = Block(
            version="1.0",
            previous_hash=previous_hash,
            timestamp=current_timestamp,
            hash=block_hash,
            transactions=transactions
        )

        # Agora, vamos ligar o novo bloco à corrente.
        # Se a corrente estava vazia...
        if self.head is None:
            self.head = new_block # ...o novo bloco é o primeiro...
            self.tail = new_block # ...e também o último.
        # Se a corrente já tinha blocos...
        else:
            self.tail.next_block = new_block # ...o antigo último bloco aponta para o novo.
            new_block.previous_block = self.tail # ...e o novo aponta de volta para o antigo último.
            self.tail = new_block # ...e o novo bloco passa a ser a cauda da corrente.

        self.size += 1 # Mais um bloco para a conta!

    # Para "cuscar" a blockchain e ver todos os blocos.
    def mostrar_blockchain(self):

        current = self.head # Começa a ver a partir do primeiro bloco.
        i = 0 # Contador para sabermos o número do bloco.

        # Se não houver blocos, avisa e sai.
        if not current:
            print("A blockchain está vazia.")
            return

        # Enquanto houver blocos para ver...
        while current:
            # Formata o timestamp para uma data legível por humanos.
            ts = datetime.fromtimestamp(current.timestamp).strftime('%Y-%m-%d %H:%M:%S')

            # Imprime os detalhes do bloco atual de forma organizada.
            print(f"Bloco {i}:")
            print(f"   Versão: {current.version}")
            print(f"   Timestamp: {ts}")
            print(f"   Transações: {current.transactions}")
            print(f"   Hash: {current.hash}")
            print(f"   Hash Anterior: {current.previous_hash}")

            print("-" * 40) # Uma linha para separar os blocos.

            current = current.next_block # Passa para o próximo bloco da corrente.
            i += 1 # Incrementa o contador.

'''
# Esta parte é só para testar se a geringonça funciona.
if __name__ == "__main__":
    from datetime import datetime # Importar datetime para o teste

    blockchain = SimpleBlockchain() # Cria uma nova blockchain.
    blockchain.add_block("Alice envia 10 para Bob") # Adiciona o primeiro bloco.
    time.sleep(1) # Espera 1 segundo para o timestamp ser diferente.
    blockchain.add_block("Bob envia 5 para Charlie") # Adiciona o segundo.

    print("\n--- ESTADO FINAL DA BLOCKCHAIN ---")
    blockchain.mostrar_blockchain() # Mostra o resultado final.
    print(f"Tamanho total: {blockchain.size} blocos")
'''