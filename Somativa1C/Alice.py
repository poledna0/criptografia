from socket import socket, AF_INET, SOCK_DGRAM
import RSALib as RSA
import AESLib as AES
import os

pastaChaves = 'Chaves_Alice'

print('ESTA TELA PERTENCE A ALICE - PRECISA EXECUTAR ANTES')

s = socket(AF_INET, SOCK_DGRAM) # vimos em Conectividade ...
s.bind(('', 9999))

# A) ALICE CARREGA AS CHAVES PUBLICA E PRIVADA
# -- substitua o None pelos comandos corretos (RSA)
caminho_chave_privada = os.path.join(pastaChaves, 'chaveprivada.pem')
chavePriObj = RSA.carregaChavePrivada(caminho_chave_privada)
caminho_chave_publica = os.path.join(pastaChaves, 'chavepublica.pem')
chavePubObj = RSA.carregaChavePública(caminho_chave_publica)

# ALICE AGUARDA MENSAGEM DE BOB COM A MENSAGEM CIFRADA E A CHAVE SECRETA CIFRADA
# -- não precisa fazer nada aqui 
print(f'Aguardando a Mensagem ...') 
data, addr = s.recvfrom(1024) 

print('Recebi a mensgem concatenada: ', data)

partes  = data.split(b'\n')
ciphertext = partes[0]
chaveCifrada = partes[1]

print('Mensagem cifrada recebida: ', ciphertext)
print('Chave secreta cifrada: ', chaveCifrada)
    

# B) ALICE DESCRIPTOGRAFA A chave secreta com sua chave privada (RSA)
# -- substitua None pela chamada correta
chaveSecreta = RSA.decifraComPrivada(chaveCifrada, chavePriObj)

# C) ALICE decriptografa a mensagem com a chave secreta (AES)
# -- substitua None pela chamada correta
plaintext = AES.decifraMensagem(ciphertext,chaveSecreta)

print(f'Recebi a mensagem: ', plaintext)   
   




