import json
from AES_code import AES
from ECC_code import ECC
import converter
def main():
    input_file = input("Name of file in test folder: ")
    file_type = input_file.split(".")[1]
    multimedia_data = converter.fileToBase64("test_files/" + input_file)
    print(multimedia_data[0:100])
    aes_key = 57811460909138771071931939740208549692
    # Encrypt  AES_key with ECC public key
    ecc_obj_AESkey = ECC.ECC()
    private_key = 59450895769729158456103083586342075745962357150281762902433455229297926354304
    public_key = ecc_obj_AESkey.gen_pubKey(private_key)
    (C1_aesKey, C2_aesKey) = ecc_obj_AESkey.encryption(public_key, str(aes_key))
    # Encrypt the multimedia_data with AES algorithm
    print(aes_key)
    aes = AES.AES(aes_key)
    encrypted_multimedia = aes.encryptBigData(multimedia_data)
    print(encrypted_multimedia)
    data_for_ecc = converter.makeSingleString(encrypted_multimedia)
    print(data_for_ecc)
    # Encrypt the encrypted_multimedia with ECC
    ecc = ECC.ECC()
    (C1_multimedia, C2_multimedia) = ecc.encryption(public_key, data_for_ecc)
    cipher = {
        "file_type": file_type,
        "C1_aesKey": C1_aesKey,
        "C2_aesKey": C2_aesKey,
        "C1_multimedia": C1_multimedia,
        "C2_multimedia": C2_multimedia,
        "private_key": private_key
    }
    with open('cipher.json', 'w') as fp:
        json.dump(cipher, fp)
    print('Encryption Done ')
if __name__ == "__main__":
    main()
