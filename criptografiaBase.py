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

def hash_(mensagem):
    """
        Para cada letra da mensagem:

        pega no seu valor numérico (com ord)

        multiplica por uma potência de um número primo

         soma tudo

    Args:
        mensagem (str): A mensagem a ser transformada em hash.

    Returns:
        int: Valor hash da mensagem.
    """
    hash_valor = 0
    primo = 31  # número primo para espalhar os valores

    for i, caractere in enumerate(mensagem): # ciclo que passa por cada letra da mensagem uma por uma.
        # ord(caractere) dá o código numérico do caractere (A função ord() converte o caractere em número, usando a tabela Unicode. ord('A') -> 65)
        hash_valor += (ord(caractere) * (primo ** i)) # multiplicar cada código de letra por uma potência de um número primo (neste caso, 31) (Para a letra na posição 0, usamos 31^0 = 1 Para a posição 1, usamos 31^1 = 31 Para a posição 2, usamos 31^2 = 961)

    # Reduzir o resultado para um intervalo (por exemplo 0 a 99999)
    hash_valor = hash_valor % 100000 #("garantir que o valor final do hash não cresce indefinidamente e fica sempre dentro de um intervalo fixo de valores.")
 
    return hash_valor

# Exemplo de uso
mensagem_original = "Ola mundo"
hash_resultado = hash(mensagem_original)

print(f"Mensagem original: {mensagem_original}")
print(f"Hash (mais simples...): {hash_resultado}")
