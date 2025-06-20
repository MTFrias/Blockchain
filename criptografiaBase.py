def cifra_cesar_ex(texto, deslocamento):
    resultado = ""
    print(f"\n--- Cifrar com deslocamento {deslocamento} ---")
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            pos_inicial = ord(char) - base
            pos_final = (pos_inicial + deslocamento) % 26
            char_cifrado = chr(pos_final + base)
            
            print(f"Letra '{char}' -> posição {pos_inicial} -> posição cifrada {pos_final} -> letra '{char_cifrado}'")
            
            resultado += char_cifrado
        else:
            print(f"Caracter '{char}' não é letra -> mantido igual")
            resultado += char
    return resultado

def decifra_cesar_pf(texto_cifrado, deslocamento):
    print(f"\n--- Decifrar com deslocamento {deslocamento} ---")
    return cifra_cesar_ex(texto_cifrado, -deslocamento)

# Exemplo
mensagem = "Mensagem Secreta!"
deslocamento = 2

# Cifrar
cifrada = cifra_cesar_ex(mensagem, deslocamento)
print("\nTexto cifrado final:", cifrada)

# Decifrar
decifrada = decifra_cesar_pf(cifrada, deslocamento)
print("\nTexto decifrado final:", decifrada)

'''
Diffie-Hellman
'''
# Parâmetros públicos (conhecidos por todos)
p = 23  # número primo (p serve para "cortar" os resultados (resto da divisão por p, ou seja, (valor) % p).)
g = 5   # gerador (número primitivo módulo p) (g é um número especial chamado gerador, usado para criar as chaves.)

# Chave privada da Alice (secreta) 
a = 6 # (Alice escolhe secretamente o número a = 6.)

# Chave pública da Alice
A = (g ** a) % p

# Chave privada do Bob (secreta)
b = 15 # ( Bob escolhe secretamente o número b = 15. )
# Chave pública do Bob
B = (g ** b) % p

# Troca-se A e B publicamente.

# Alice calcula a chave secreta (Depois de Alice receber B de Bob, ela calcula:)
chave_secreta_alice = (B ** a) % p

# Bob calcula a chave secreta (Bob faz o mesmo com A recebido de Alice:)
chave_secreta_bob = (A ** b) % p

# É garantido que ambas as contas vão dar exatamente o mesmo número! 

# Ambas as chaves secretas devem ser iguais
print(f"Chave secreta da Alice: {chave_secreta_alice}")
print(f"Chave secreta do Bob:   {chave_secreta_bob}")
print("\n\n")

'''
Função de Hash

'''

def simple_hash(text: str, bucket_size: int) -> int:
    """
    Calcula um hash simples e didático para uma string de texto.

    O objetivo é mapear o texto para um número inteiro dentro de um intervalo
    definido por 'bucket_size'.

    Args:
        text: O texto de entrada para gerar o hash.
        bucket_size: O número de "gavetas" ou "buckets" disponíveis.
                     O hash final será um número entre 0 e bucket_size - 1.

    Returns:
        Um número inteiro que representa o hash do texto.
    """
    # 1. Começamos com um valor inicial para o nosso hash, geralmente 0.
    hash_value = 0
    
    # Usar um número primo ajuda a distribuir melhor os valores do hash,
    # evitando colisões simples. 31 é uma escolha comum e eficiente.
    prime_number = 31

    # 2. Percorremos cada caracter do texto de entrada.
    for char in text:
        # 3. Convertemos o caracter para o seu valor numérico (padrão ASCII/Unicode).
        # Ex: ord('A') -> 65, ord('B') -> 66
        char_code = ord(char)
        
        # 4. Esta é a "magia". Combinamos o valor atual do hash com o novo caracter.
        # A multiplicação pelo número primo garante que a posição de cada caracter
        # importa. "abc" terá um hash diferente de "cba".
        hash_value = (hash_value * prime_number + char_code)

    # 5. Finalmente, usamos o operador módulo (%) para garantir que o resultado
    # final esteja dentro do nosso intervalo de "gavetas" (de 0 a bucket_size - 1).
    final_hash = hash_value % bucket_size
    
    return final_hash

# Exemplo de uso
mensagem_original = "Ola mundo"
hash_resultado = hash(mensagem_original)

print(f"Mensagem original: {mensagem_original}")
print(f"Hash (mais simples...): {hash_resultado}")
