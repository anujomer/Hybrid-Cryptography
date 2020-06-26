import json
from AES_code import AES
from ECC_code import ECC
import converter

def main():
    with open('cipher.json') as f:
        data = json.load(f)
    C1_aesKey = data["C1_aesKey"]
    C2_aesKey = data["C2_aesKey"]
    private_key = data["private_key"]
    file_type = data["file_type"]
    # Decrypt with ECC to get the AES key
    ecc_AESkey = ECC.ECC()
    decryptedAESkey = ecc_AESkey.decryption(C1_aesKey, C2_aesKey, private_key)
    C1_multimedia = data["C1_multimedia"]
    C2_multimedia = data["C2_multimedia"]
    # Decrypt the data with ECC
    ecc_obj = ECC.ECC()
    encrypted_multimedia = ecc_obj.decryption(C1_multimedia, C2_multimedia, private_key)
    clean_data_list = converter.makeListFromString(encrypted_multimedia)
    # Decrypt with AES
    aes_obj = AES.AES(int(decryptedAESkey))
    decrypted_multimedia = aes_obj.decryptBigData(clean_data_list)
    # Decode from Base64 to the corresponding fileToBase64
    output_file = "Decrypted_file."+file_type
    converter.base64ToFile(decrypted_multimedia, output_file)
    print("Decryption Done and file saved in project folder with name Decrypted_file.")

if __name__ == "__main__":
    main()