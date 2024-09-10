from socket import socket, AF_INET, SOCK_DGRAM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat,PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, load_pem_public_key, load_pem_parameters

# ESTE É UM EXEMPLO DE PROTOCOLO DE NEGOCICAÇÃO DE CHAVES
# -- Ele permite combinar uma chave secreta aleatória pela rede
# -- O ECDH é o algoritmo de negociação de chaves mais usado atualmente

#************************************************
# NESTE EXEMPLO BOB FAZ O PAPEL DE CLIENTE UDP
# PRECISA EXECUTAR BOB DEPOIS DA ALICE
#************************************************

s = socket(AF_INET, SOCK_DGRAM)

#---------------------------------------------------------------------
# Complete o código substituindo o None pela chamada correta
# -- use o código ECCcripto.py fornecido no AVA como exemplo

# 1) BOB GERA AS CHAVES PÚBLICA E PRIVADA
# -- substitua None pela chamada correta usando o exemplo em ECCcripto.py

bob_private_key = ec.generate_private_key( ec.SECP384R1() )
bob_public_key = bob_private_key.public_key()

# 2) BOB CONVERTE A CHAVE PÚBLICA (objeto Python) PARA PEM (formato base64)
# -- substitua None pela chamada correta usando o exemplo em ECCcripto.py
# -- OBS. PEM é um formato padrão que permite que Bob fale com o Alice mesmo que ela não esteja usando Python
bob_pubkey_PEM = bob_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

print('\nBob gerou uma chave pública a partir do seu próprio segredo')
print(bob_pubkey_PEM)

# 3) BOB ENVIA UM HELLO PARA ALICE PARA INCIAR O PROTOCOLO E RECEBER A CHAVE PÚBLICA DA ALICE
# -- não precisa fazer nada nesse passo
ALICE = ('127.0.0.1', 9999)
s.sendto('HELLO'.encode(), ALICE ) 

print('\nBOB está aguardando a chave pública da Alice')
alice_pubkey_PEM, addr = s.recvfrom(1024)
if addr != ALICE:
    print('\nBob recebeu uma mensagem de origem desconhecida')
    exit()

print('\nBob recebeu a chave pública de Alice')
print(alice_pubkey_PEM)

# 4) BOB TRANSMITE SUA CHAVE PÙBLICA 
# -- troque string CHAVE PUBLICA pela chave publica em formato base64 (e remova o encode)
s.sendto(bob_pubkey_PEM, ALICE )     

# 5) BOB CONVERTE A CHAVE PEM PARA OBJETO PYTHON
# -- substitua None pela chamada correta usando o exemplo em ECCcripto.py 
chave_publica_alice = load_pem_public_key(alice_pubkey_PEM) 

# 6) BOB GERA UM SEGREDO COMPARTILHADO USANDO A CHAVE PÚBLICA DE BOB E SUA PŔOPRIA CHAVE PRIVADA
# -- substitua None pela chamada correta usando o exemplo em ECCcripto.py 
shared_key_bob = bob_private_key.exchange(ec.ECDH(), chave_publica_alice)

if shared_key_bob:
    print('\nBob gerou um segredo compartilhado')
    print('Tamanho do segredo (bytes): ', len(shared_key_bob))
    print(shared_key_bob.hex())

# 7) BOB CONVERTE O SEGREDO COMPARTILHADO EM UMA CHAVE USANDO UM ALGORITMO DE HASHING
# -- substitua None pela chamada correta usando o exemplo em ECCcripto.py 
chave_secreta_bob = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=None,
    info=b'handshake data',
).derive(shared_key_bob)

print(chave_secreta_bob)
if chave_secreta_bob:
    
    print('\nBob gerou uma chave secreta a partir do segredo')
    print(chave_secreta_bob.hex())
    print(f'Tamanho da chave (bytes): {len(chave_secreta_bob)* 8} bits')
        





