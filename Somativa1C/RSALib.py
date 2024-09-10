# ver RSA: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from base64 import b64encode, b64decode


def geraChavePrivada(tamanho : int, arquivo : str = None) -> tuple[object, bytes]:
    '''
    Gera a chave privada e salva (opcionalmente) em arquivo se o nome for fornecido
    - tamanho: quantidade de bits da chave privada (1024, 2048 ou superior)
    - arquivo (opcional): nome do arquivo onde a chave privada será salva (usar a extensão .pem)
    - RETORNO: tupla com dois valores: chave privada como objeto e como base64
    '''

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamanho,
    )

    if arquivo is not None:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
        with open(arquivo, "wb") as key_file:
            key_file.write(private_pem)
        
    return private_key, private_pem

def geraChavePublica(private_key : object, arquivo : str = None) -> tuple[object, bytes]:
    '''
    Calcula (extrai) a chave pública a partir da chave privada e salva (opcionalmente) em arquivo se o nome for fornecido
    - private_key: chave privada como objeto 
    - arquivo (opcional): nome do arquivo onde a chave pública será salva (usar a extensão .pem)
    - RETORNO: tupla com dois valores: chave pública como objeto e como base64
    '''
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if arquivo is not None:
        with open(arquivo, "wb") as key_file:
            key_file.write(public_pem)

    return public_key, public_pem
 
def carregaChavePrivada(arquivo : str) -> object :
    '''
    Carrega a chave privada a partir de um arquivo (a chave não deve ser gerada a cada vez que o algoritmo é executado)
    - arquivo: caminho para o arquivo com a chave privada (em formato PEM)
    - RETORNO: objeto com a chave privada
    '''
    with open(arquivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def carregaChavePública(arquivo : str) -> object:
    '''
    Carrega a chave publica a partir de um arquivo (a chave não deve ser gerada a cada vez que o algoritmo é executado)
    - arquivo: caminho para o arquivo com a chave publica (em formato PEM)
    - RETORNO: objeto com a chave publica
    '''
    with open(arquivo, "rb") as key_file:        
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

def cifraComPublica(plaintext : bytes, public_key : object) -> bytes:
    '''
    - Cifra uma string ou bytes usando a chave pública.
    - plaintext: dados que serão cifrados, fornecidos como string ou como bytes
    - public_key: chave pública no formato de objeto
    - RETORNO: dados cifrados como base64
    '''

    if not isinstance(plaintext, bytes):
        raise(Exception('Os dados precisam estar em bytes'))
    
    cipherbytes = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ciphertext = b64encode(cipherbytes)

    return ciphertext

def decifraComPrivada(ciphertext : bytes, private_key : object) -> bytes:
    '''
    Decifra dados criptografados com a chave pública, usando a chave privada correspondente.
    - ciphertext: dados criptografados com a chave pública em formato base64
    - private_key: chave privada no formato de objeto
    - RETORNO: dados decifrados 
    '''

    cipherbytes = b64decode(ciphertext)
    plainbytes = private_key.decrypt(
        cipherbytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plainbytes


# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":


    # PARTE 1: GERAÇÃO DAS CHAVES

    # Pasta atual onde o script está sendo executado
    print("Diretorio:", os.getcwd(), '\n')
    
    pasta_Alice = 'Chaves_Alice'
    pasta_Bob = 'Chaves_Bob'

    # Cria as pasta que serão os repositórios das chaves
    if not os.path.isdir(pasta_Alice): 
        os.makedirs(pasta_Alice) 
    if not os.path.isdir(pasta_Bob): 
        os.makedirs(pasta_Bob)
    
    # Obj são estruturas usadas pelo algoritmo em Python, PEM são chaves transportáveis (serializadas) em formato base64
    # Observe que o formato PEM é um formato padrão independente da linguagem, mas Obj é um formato do Python
    caminho_chave_privada = os.path.join(pasta_Alice,"chaveprivada.pem")
    chavePriObj, chavePriPEM = geraChavePrivada(2048, caminho_chave_privada)

    caminho_chave_publica = os.path.join(pasta_Alice,"chavepublica.pem")
    chavePubObj, chavePubPEM = geraChavePublica(chavePriObj, caminho_chave_publica)

    print('Chave PRIVADA DA ALICE (não pode ser conhecida por mais ninguém):')
    print(chavePriPEM.decode(), '\n')
    print('Chave PUBLICA DA ALICE (quem quiser enviar mensagens para Alice precisa ter uma cópia):')
    print(chavePubPEM.decode(), '\n')      



    # PARTE 2: DEMONSTRAÇÃO DO USO DAS FUNÇÕES

    # A chave publica carregada do arquivo está formato PEM, então é necessário convertê-la antes de usar
    chavePubObj2 = carregaChavePública(caminho_chave_publica)

    # Criptografa com a chave pública (o resultado é base64)
    # -- encode não é necessário se os dados já estiverem em bytes
    ciphertext = cifraComPublica('CHAVE SECRETA DO AES'.encode(), chavePubObj2 )

    print('CHAVE SECRETA CIFRADA (base64):')
    print(ciphertext, '\n')

    # Descriptografa com a chave privada (resultado em bytes)
    chavePriObj2 = carregaChavePrivada(caminho_chave_privada)
    plaintext = decifraComPrivada(ciphertext, chavePriObj2)
    
    print('CHAVE SECRETA DECIFRADA (formato original):')
    print(plaintext)






