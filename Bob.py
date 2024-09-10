from socket import socket, AF_INET, SOCK_DGRAM
import os
import RSALib as RSA
import AESLib as AES

ALICE = ('127.0.0.1', 9999)
pastaChaves = 'Chaves_Bob'

print('ESTA TELA PERTENCE A BOB')

s = socket(AF_INET, SOCK_DGRAM) # vimos em Conectividade ...

try:

    # A) BOB CARREGA A CHAVE PÚBLICA DA ALICE (COMO ELE OBTEVE?!?)
    # -- é preciso converter a chave de base64 para o objeto do Python
    caminho_chave_publica = os.path.join(pastaChaves, 'chavepublica.pem')
    chavePubObj = RSA.carregaChavePública(caminho_chave_publica)

    # B) BOB GERA UMA CHAVE SECRETA ALEATÓRIA (AES)
    chavesecreta, chavePEM = AES.geraChave(128)

    # C) BOB CRIPTOGRAFA UMA MENSAGEM USANDO A CHAVE SECRETA (AES)
    # -- substitua o nome *** BOB *** pelo seu nome ou da Equipe
    # -- substitua o conteúdo de mensagemCifrada
    equipe = 'GRUPO 1'
    mensagem = f'MENSAGEM ENVIADA DA MELHOR EQUIPE -> {equipe}!'
    mensagemCifrada = AES.cifraMensagem(mensagem, chavesecreta)

    # D) BOB CRIPTOGRAFA A CHAVE SECRETA (EM BYTES) COM A CHAVE PÚBLICA DA ALICE (RSA)
    # -- observe que não é necessário usar encode
    # -- substitua o conteúdo de chaveCifrada
    
    chaveCifrada = RSA.cifraComPublica(chavesecreta, chavePubObj)

    # BOB ENVIA A MENSAGEM CIFRADA E CHAVE SECRETA CRIPTOGRAFADA PARA ALICE
    #    -- se você fez tudo certo, não precisa fazer nada aqui
    dados = mensagemCifrada + b'\n' + chaveCifrada
    s.sendto(dados, ALICE )    
    print('Bob envia mensagem para ALICE:', dados)


except Exception as e:
    print(e)

# ATENCAO: A entrega desta atividade são as mensagens que aparecem nas telas de BOB e ALICE
# -- As chaves são aleatórias então duas equipes não podem ter as mesmas chaves




