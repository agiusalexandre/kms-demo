__author__ = 'aaagius'
import boto3
from boto3.session import Session
from boto3.s3.transfer import S3Transfer
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import random
import os
import struct
import base64

MASTER_KEY_ARN = 'YOUR-ARN'
S3_BUCKET = 'demo-cmk'
#DIRECTORY = '/Users/aaagius/Desktop'
#FILENAME = 'wifi.jpg'
REGION = 'eu-west-1'


###########################################################################
# Option 1: Using a CMK stored in AWS KMS
# Scenario : Encrypt / Decrypt on client side with AES lib
#            AWS KMS is use to protect the Data key
#            AWS s3 store the ciphered data & the ciphered key
#####
# Call Kms API to Generate a Data Key
# Use the PyCryptodome AES module for AES block cipher ( https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html )
# Create an AES key with the returned  256 bit generated KMS key
# Encode a plain text with the cipher key
# Decode the cipher text with the cipher key
###########################################################################

def kmsKeyDemo():
    print('\n Option 1: Using a CMK stored in AWS KMS \n')

    #
    # Create a KMS Client object
    #
    session = Session(profile_name='default', region_name=REGION)
    kms = session.client('kms')

    #
    # Generate a Data Key (encoded with my Master Key in KMS)
    #    Response {
    #     'CiphertextBlob': b'bytes',
    #     'Plaintext': b'bytes',
    #     'KeyId': 'string'
    #    }
    # A plaintext version of the data key that the client uses to encrypt the object data
    # A cipher blob of the same data key that the client uploads to Amazon S3 as object metadata

    key = kms.generate_data_key(KeyId=MASTER_KEY_ARN, KeySpec='AES_256')

    keyPlain = key['Plaintext']
    keyCipher = key['CiphertextBlob']

    print(' Plain text generated key = %s \n ' % keyPlain)
    print(' Ciphered text Blob = %s \n ' % keyCipher)

    #
    # Encode a plain text with the data key
    #
    obj = AES.new(keyPlain, AES.MODE_CBC, b'This is an IV123')
    msgPlain = b'Hello world of cryptography w/managed keys'
    msgCipher = obj.encrypt(pad(msgPlain, 16))
    print('AES encrypt \n')
    print('Plain text msg to encrypt = %s \n' % msgPlain)
    print('Cipher message = %s \n' % base64.b64encode(msgCipher))

    #
    # Now, we're supposed to trash the clear text key
    # and save the cipher version of the key
    #
    # s3_client = boto3.client('s3')

    # s3_client.create_bucket(Bucket=S3_BUCKET,CreateBucketConfiguration={
    # 'LocationConstraint': 'eu-west-1'})

    # response = s3_client.upload_file(msgCipher, S3_BUCKET, 'msgCipher')
    # response = s3_client.upload_file(keyCipher, S3_BUCKET, 'keyCipher')

    #
    # Later, we ask KMS to create a plain text version of the cipher key
    # Send the cipher blob to AWS KMS to get the plaintext version of the data key
    #   -> so we can decrypt the object data
    #

    print('AES decrypt \n')
    key = kms.decrypt(CiphertextBlob=keyCipher)
    keyPlain = key['Plaintext']

    #
    # and we decrypt our cipher text
    #
    obj = AES.new(keyPlain, AES.MODE_CBC, b'This is an IV123')
    plainText = unpad(obj.decrypt(msgCipher), 16)

    print(f'Plain text msg decrypted = {plainText} \n')


###########################################################################
# Option 2: Using a CMK stored in AWS KMS & Using AWS KMS encrypt-decrypt operation
# Scenario :
#            AWS KMS is use to protect the Data key & for encrypt-Decrypt operation
#            AWS s3 store the ciphered data & the ciphered key
###########################################################################

def kmsEncryptionDemo():

    print('\n Option 2: Using a CMK stored in AWS KMS & Using AWS KMS encrypt-decrypt operation \n')

    #
    # Create a KMS Client object
    #
    session = Session(profile_name='default', region_name=REGION)
    kms = session.client('kms')

    password = 'this is my super secret password'
    print(f'Plaintext password  = {password} \n')

    #
    # Cipher a plain text object using your master key
    #
    ret = kms.encrypt(KeyId=MASTER_KEY_ARN, Plaintext=password)
    print('AWS KMS encrypt \n')
    print(f"Cipher password    = {base64.b64encode(ret['CiphertextBlob'])} \n")

    #
    # Decrypt a ciphered text
    #
    ret = kms.decrypt(CiphertextBlob=ret['CiphertextBlob'])
    print('AWS KMS decrypt \n')
    print(f"Plaintext password = {ret['Plaintext']} \n")


# file encryption code taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def S3KMSDemo():

    #
    # Create a KMS Client object
    #
    session = Session(profile_name='default', region_name='us-east-1')
    kms = session.client('kms')

    #
    # Generate a Data Key (encoded with my Master Key in KMS)
    #
    key = kms.generate_data_key(KeyId=MASTER_KEY_ARN, KeySpec='AES_256')
    keyPlain = key['Plaintext']
    keyCipher = key['CiphertextBlob']

    #
    # Encode a file with the data key
    #
    print('Initializing encryption engine')
    iv = Random.new().read(AES.block_size)
    chunksize = 64*1024
    encryptor = AES.new(keyPlain, AES.MODE_CBC, iv)

    print(f'KMS Plain text key = {base64.b64encode(keyPlain)} ')
    print(f'KMS Encrypted key  = {base64.b64encode(keyCipher)} ')

    in_filename = os.path.join(DIRECTORY, FILENAME)
    out_filename = in_filename + '.enc'
    filesize = os.path.getsize(in_filename)

    print('Encrypting file')
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            chunk = infile.read(chunksize)
            while len(chunk) != 0:
                if len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))
                chunk = infile.read(chunksize)

    #
    # Store encrypted file on S3
    # Encrypted Key will be stored as meta data
    #
    print('Storing encrypted file on S3')
    metadata = {
        'key': base64.b64encode(keyCipher).decode('ascii')
    }

    s3 = session.client('s3')
    s3.upload_file(out_filename, S3_BUCKET, out_filename,
                   ExtraArgs={'Metadata': metadata})
    os.remove(out_filename)

    ##
    # Later ...
    ##

    #
    # Download Encrypted File and it's metadata
    #
    print('Download file and meta data from S3')
    transfer = S3Transfer(s3)
    transfer.download_file(S3_BUCKET, out_filename, out_filename)

    # retrieve meta data
    import boto3
    s3 = boto3.resource('s3')
    object = s3.Object(S3_BUCKET, out_filename)
    # print object.metadata

    keyCipher = base64.b64decode(object.metadata['key'])

    # decrypt encrypted key
    print('Decrypt ciphered key')
    key = kms.decrypt(CiphertextBlob=keyCipher)
    keyPlain = key['Plaintext']
    print(f'KMS Plain text key = {base64.b64encode(keyPlain)}')
    print(f'KMS Encrypted key  = {base64.b64encode(keyCipher)}')

    #
    # Decrypt the file
    #
    print('Decrypt the file')

    in_filename = out_filename
    out_filename = in_filename + '.jpg'
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(keyPlain, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            chunk = infile.read(chunksize)
            while len(chunk) != 0:
                outfile.write(decryptor.decrypt(chunk))
                chunk = infile.read(chunksize)

            outfile.truncate(origsize)

    # Cleanup S3
    object.delete()

    print(
        f'Done.\n\nYour file {out_filename} should be identical to original file {os.path.join(DIRECTORY, FILENAME)}')


###########################################################################
# Option 3: Using AWS Encryption SDK is a client-side encryption library designed
# to make it easy for everyone to encrypt and decrypt data using industry standards and best practices
# https://aws-encryption-sdk-python.readthedocs.io/en/latest/index.html
# Scenario :
#            AWS KMS is use to protect the Data key & for encrypt-Decrypt operation
#            AWS s3 store the ciphered data & the ciphered key
###########################################################################
def encryptionSDKDemo():
    import aws_encryption_sdk
    from aws_encryption_sdk.identifiers import CommitmentPolicy


    #
    # Create AWS encryption sdk client with 
    #
    client = aws_encryption_sdk.EncryptionSDKClient(        
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[ MASTER_KEY_ARN])

    #
    # My secret string
    #
    my_plaintext = b'This is some super secret data!'
    print(' Plain text to encrypt = %s \n ' % my_plaintext)

    #
    # Let's encrypt the plaintext data
    #
    print(" let's encrypt ! \n")
    my_ciphertext, encryptor_header = client.encrypt(
        source=my_plaintext,
        key_provider=kms_key_provider
    )
    print(' My ciphered text  = %s \n ' % my_ciphertext)

    #
    # Let's decrypt the ciphertext data
    #
    print(" let's decrypt ! \n")
    decrypted_plaintext, decryptor_header = client.decrypt(
        source=my_ciphertext,
        key_provider=kms_key_provider
    )
    print(' My ciphered text  decrypt = %s \n ' % decrypted_plaintext)


def kmsSign():

    MESSAGE_TO_SIGN = b'This is the message to sign'
    SIGNATURE_KEY_ARN = 'arn:aws:kms:us-east-1:486652066693:key/c74eed44-ecb6-424b-9b1e-1a305ab64a4e'

    #
    # Create a KMS Client object
    #
    session = Session(profile_name='default', region_name='us-east-1')
    kms = session.client('kms')

    #
    # Sign a piece of text
    #
    print('Signing a simple text ')
    response = kms.sign(
        KeyId=SIGNATURE_KEY_ARN,
        Message=MESSAGE_TO_SIGN,
        MessageType='RAW',
        SigningAlgorithm='RSASSA_PSS_SHA_256'
    )

    signature = response['Signature']

    #
    # Show signature
    #
    print(f"Signature : {base64.b64encode(signature).decode('ascii')}")

    #
    # verify signature
    #
    response = kms.verify(
        KeyId=SIGNATURE_KEY_ARN,
        Message=MESSAGE_TO_SIGN,
        MessageType='RAW',
        Signature=signature,
        SigningAlgorithm='RSASSA_PSS_SHA_256'
    )

    if response['SignatureValid'] == True:
        print('Signature is valid')
    else:
        print('Signature is NOT valid')


def kmsAsymetricEncrypt():

    # small amount of data only
    # see https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.encrypt
    MESSAGE_TO_CRYPT = b'This is the message to encrypt'
    ASYNC_KEY_ARN = 'arn:aws:kms:us-east-1:486652066693:key/5a681bd7-d1f9-44f7-839f-576601255490'

    #
    # Create a KMS Client object
    #
    session = Session(profile_name='default', region_name='us-east-1')
    kms = session.client('kms')

    #
    # Cipher a plain text object using your master key
    #
    print('Use public key to encrypt a short text')
    ret = kms.encrypt(
        KeyId=ASYNC_KEY_ARN,
        Plaintext=MESSAGE_TO_CRYPT,
        EncryptionAlgorithm='RSAES_OAEP_SHA_256'
    )
    print(f"Ciphered text     = {base64.b64encode(ret['CiphertextBlob'])}")

    #
    # Decrypt a ciphered text
    #
    print('Use private key to decrypt a short text')
    ret = kms.decrypt(
        KeyId=ASYNC_KEY_ARN,
        CiphertextBlob=ret['CiphertextBlob'],
        EncryptionAlgorithm='RSAES_OAEP_SHA_256'
    )
    print(f"Plaintext message = {ret['Plaintext']}")


if __name__ == '__main__':
    kmsKeyDemo()
    kmsEncryptionDemo()
    encryptionSDKDemo()
