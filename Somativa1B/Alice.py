from socket import socket, AF_INET, SOCK_DGRAM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat,PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, load_pem_public_key, load_pem_parameters

# ESTE É UM EXEMPLO DE PROTOCOLO DE NEGOCICAÇÃO DE CHAVES
# -- Ele permite combinar uma chave secreta aleatória pela rede
# -- O ECDH é o algoritmo de negociação de chaves mais usado atualmente

#***************************************
# NESTE EXEMPLO ALICE FAZ O PAPEL DE SERVIDOR UDP
# PRECISA EXECUTAR ALICE ANTES DE BOB!!!
#***************************************

s = socket(AF_INET, SOCK_DGRAM)
s.bind(('', 9999))

#---------------------------------------------------------------------
# Complete o código substituindo o None pela chamada correta
# -- use o código ECCcripto.py fornecido no AVA como exemplo

# 1) ALICE GERA AS CHAVES PÚBLICA E PRIVADA
# -- substitua None pela chamada correta usando o exemplo em ECCcripto.py

alice_private_key = ec.generate_private_key( ec.SECP384R1() )
alice_public_key = alice_private_key.public_key()

# 2) ALICE CONVERTE A CHAVE PÚBLICA (objeto Python) PARA PEM (formato base64)
# -- substitua None pela chamada correta usando o exemplo em ECCcripto.py
# -- OBS. PEM é um formato padrão que permite que ALICE fale com o BOB mesmo que ele não esteja usando Python
alice_pubkey_PEM = alice_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


print('\nAlice gerou uma chave pública a partir do seu próprio segredo')
print(alice_pubkey_PEM)

print('\nAguardando um HELLO do BOB...') 
data, addr = s.recvfrom(1024) 
BOB = addr
datastr = data.decode()   
print(f'\nAlice recebeu {datastr} de {BOB}')

if datastr == "HELLO":
    # 3) ALICE TRANSMITE SUA CHAVE PÙBLICA 
    # -- troque string CHAVE PUBLICA pela chave publica em formato base64 (e remova o encode)
    s.sendto(alice_pubkey_PEM, BOB )     
    

    # 4) ALICE RECEBE A CHAVE PUBLICA DE BOB (em formato PEM) 
    # -- OBS. o que vem pela rede é sempre BYTES (não precisa faze nada aqui)
    print('\nAlice está aguardando a chave pública da Bob')
    bob_pubkey_PEM, addr = s.recvfrom(1024)
    if addr != BOB:
        print('\nAlice recebeu uma mensagem de origem desconhecida')
        exit()

    print('\nAlice recebeu a chave pública de Bob')
    print(bob_pubkey_PEM)

    # 5) ALICE CONVERTE A CHAVE PEM PARA OBJETO PYTHON
    # -- substitua None pela chamada correta usando o exemplo em ECCcripto.py 
    chave_publica_bob = load_pem_public_key(bob_pubkey_PEM) 
    

    # 6) ALICE GERA UM SEGREDO COMPARTILHADO USANDO A CHAVE PÚBLICA DE BOB E SUA PŔOPRIA CHAVE PRIVADA
    # -- substitua None pela chamada correta usando o exemplo em ECCcripto.py 
    shared_key_alice = alice_private_key.exchange(ec.ECDH(), chave_publica_bob)
    
    if shared_key_alice:
        print('\nAlice gerou um segredo compartilhado')
        print('Tamanho do segredo (bytes): ', len(shared_key_alice))
        print(shared_key_alice.hex())

    # 7) ALICE CONVERTE O SEGREDO COMPARTILHADO EM UMA CHAVE USANDO UM ALGORITMO DE HASHING
    # -- substitua None pela chamada correta usando o exemplo em ECCcripto.py 
    chave_secreta_alice = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key_alice)
    print(chave_secreta_alice)
    
    if chave_secreta_alice:
        print('\nAlice gerou uma chave secreta a partir do segredo')
        print(chave_secreta_alice.hex())
        print(f'Tamanho da chave (bytes): {len(chave_secreta_alice)* 8} bits')
    
else: 
    print('descartei uma mensagem de ', addr)




