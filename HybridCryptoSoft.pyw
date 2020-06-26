import random
import base64
from tkinter import *
import tkinter
import json
import os
import tkinter.messagebox
from tkinter import filedialog
Sbox = (
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
    202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
    183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
    4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
    9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
    83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
    208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
    81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
    205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
    96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224,
    50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231,
    200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186,
    120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112,
    62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225,
    248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140,
    161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22
)

InvSbox = (
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233,
    203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195,
    78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209,
    37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101,
    182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141,
    157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179,
    69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138,
    107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180,
    230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117,
    223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24,
    190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205,
    90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236,
    95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156,
    239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153,
    97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125
)

Rcon = (0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47,
        94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57)
class AES:
    def __init__(self, key):
        self.shiftKey(key)

    def shiftKey(self, key):
        self.roundKey = self.inputMatrix(key)

        for i in range(4, 4 * 11):
            self.roundKey.append([])
            if i % 4 == 0:
                newKey = self.roundKey[i - 4][0] ^ Sbox[self.roundKey[i - 1]
                                                                  [1]] ^ Rcon[i // 4]
                self.roundKey[i].append(newKey)

                for j in range(1, 4):
                    newKey = self.roundKey[i -
                                           4][j] ^ Sbox[self.roundKey[i - 1][(j + 1) % 4]]
                    self.roundKey[i].append(newKey)
            else:
                for j in range(4):
                    newKey = self.roundKey[i - 4][j] ^ self.roundKey[i - 1][j]
                    self.roundKey[i].append(newKey)

    def encryption(self, plainText):
        self.plainState = self.inputMatrix(plainText)

        self.addRoundKey(self.plainState, self.roundKey[:4])

        for i in range(1, 10):
            self.substituteBytes(self.plainState)  # sub bytes
            self.rowShifter(self.plainState)  # shift rows
            self.columnMixer(self.plainState)  # mix column
            self.addRoundKey(
                self.plainState, self.roundKey[4 * i: 4 * (i + 1)])

        self.substituteBytes(self.plainState)
        self.rowShifter(self.plainState)
        self.addRoundKey(self.plainState, self.roundKey[40:])

        return self.matrixOutput(self.plainState)

    def decryption(self, cipherText):
        self.cipher_state = self.inputMatrix(cipherText)

        self.addRoundKey(self.cipher_state, self.roundKey[40:])
        self.inverseRowShifter(self.cipher_state)
        self.inverseSubstituteBytes(self.cipher_state)

        for i in range(9, 0, -1):
            self.addRoundKey(self.cipher_state,
                             self.roundKey[4 * i: 4 * (i + 1)])
            self.inverseColumnMixer(self.cipher_state)
            self.inverseRowShifter(self.cipher_state)
            self.inverseSubstituteBytes(self.cipher_state)

        self.addRoundKey(self.cipher_state, self.roundKey[:4])

        return self.matrixOutput(self.cipher_state)

    def addRoundKey(self, s, k):
        for i in range(4):
            for j in range(4):
                s[i][j] = s[i][j] ^ k[i][j]

    def substituteBytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = Sbox[s[i][j]]

    def inverseSubstituteBytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = InvSbox[s[i][j]]

    def rowShifter(self, shift):
        shift[0][1], shift[1][1], shift[2][1], shift[3][1] = shift[1][1], shift[2][1], shift[3][1], shift[0][1]
        shift[0][2], shift[1][2], shift[2][2], shift[3][2] = shift[2][2], shift[3][2], shift[0][2], shift[1][2]
        shift[0][3], shift[1][3], shift[2][3], shift[3][3] = shift[3][3], shift[0][3], shift[1][3], shift[2][3]

    def inverseRowShifter(self, iShift):
        iShift[0][1], iShift[1][1], iShift[2][1], iShift[3][1] = iShift[3][1], iShift[0][1], iShift[1][1], iShift[2][1]
        iShift[0][2], iShift[1][2], iShift[2][2], iShift[3][2] = iShift[2][2], iShift[3][2], iShift[0][2], iShift[1][2]
        iShift[0][3], iShift[1][3], iShift[2][3], iShift[3][3] = iShift[1][3], iShift[2][3], iShift[3][3], iShift[0][3]

    def columnMixer(self, state):
        for i in range(4):
            t = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]
            u = state[i][0]
            state[i][0] ^= t ^ self.mixFactor(state[i][0] ^ state[i][1])
            state[i][1] ^= t ^ self.mixFactor(state[i][1] ^ state[i][2])
            state[i][2] ^= t ^ self.mixFactor(state[i][2] ^ state[i][3])
            state[i][3] ^= t ^ self.mixFactor(state[i][3] ^ u)

    def inverseColumnMixer(self, state):
        for i in range(4):
            u = self.mixFactor(self.mixFactor(state[i][0] ^ state[i][2]))
            v = self.mixFactor(self.mixFactor(state[i][1] ^ state[i][3]))
            state[i][0] ^= u
            state[i][1] ^= v
            state[i][2] ^= u
            state[i][3] ^= v

        self.columnMixer(state)
    def mixFactor(self, x):
        return (((x << 1) ^ 27) & 255) if (x & 128) else (x << 1)

    def inputMatrix(self, input):
        matrix = []
        for i in range(16):
            inputByte = (input >> (8 * (15 - i))) & 255
            if i % 4 == 0:
                matrix.append([inputByte])
            else:
                matrix[i // 4].append(inputByte)
        return matrix

    def matrixOutput(self, matrix):
        output = 0
        for i in range(4):
            for j in range(4):
                output |= (matrix[i][j] << (120 - (((i << 2) + j) << 3)))
        return output

    def encAscii(self, character):
        return ord(character) << 2

    def decAscii(self, asciiVal):
        return int(asciiVal) >> 2

    def encode(self, msg):
        encodedString = ''
        for i in msg:
            encodedString += str(self.encAscii(i))
        return encodedString

    def decode(self, encAscii_string):
        i = 0
        decodedString = ''
        while (i < len(str(encAscii_string))):
            pack = encAscii_string[i:i+3]
            decodedString += chr(self.decAscii(pack))
            i = i+3
        return decodedString

    def breakIntoChunks(self, data):
        retData = []
        dataLen = len(data)
        for i in range(0, dataLen, 12):
            temp = data[i:i+12]
            retData.append(temp)
        return retData

    def chunksToData(self, chunks):
        retData = ""
        for i in chunks:
            retData = retData+i
        return retData

    def encryptBigData(self, data):
        chuck_data = self.breakIntoChunks(data)
        retData = []
        for chunk in chuck_data:
            encrypted_chunk = self.encryption(int(self.encode(chunk)))
            encrypted_chunk = int(encrypted_chunk)
            retData.append(encrypted_chunk)
        return retData

    def decryptBigData(self, encrypted_chunks):
        data=""
        for chunk in encrypted_chunks:
            decrypted_chunk = self.decode(str(self.decryption(chunk)))
            data=data+decrypted_chunk
        return data
# Curve used: secp521r1
# Curve is in the form of : y^2 = x^3 + A * x + B
P = int(0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
A = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148
B = 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984
Gx = int(0x0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66)
Gy = int(0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
GP = (Gx, Gy)
N = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
class ECC:
    def __init__(self):
        self.h = 1
        self.k = random.getrandbits(256)

    def encAscii(self, character):
        return ord(character) << 2

    def decAscii(self, asciiVal):
        return int(asciiVal) >> 2

    def encode(self, msg):
        encodedString = ''
        for i in msg:
            encodedString += str(self.encAscii(i))
        return encodedString

    def decode(self, encAscii_string):
        i = 0
        decodedString = ''
        while (i < len(str(encAscii_string))):
            pack = encAscii_string[i:i+3]
            decodedString += chr(self.decAscii(pack))
            i = i+3
        return decodedString

    def modInverse(self, a, n=P):
        lowM = 1
        highM = 0
        low = a % n
        high = n
        while low > 1:
            r = high//low
            nm = highM-lowM*r
            new = high-low*r
            lowM, low, highM, high = nm, new, lowM, low
        return lowM % n

    def eccAddition(self, a, b):
        LamAdd = ((b[1]-a[1]) * self.modInverse(b[0]-a[0], P)) % P
        x = (LamAdd*LamAdd-a[0]-b[0]) % P
        y = (LamAdd*(a[0]-x)-a[1]) % P
        return(x, y)

    def ecTwoFold(self, a):
        Lam = ((3*a[0]*a[0]+A) * self.modInverse((2*a[1]), P)) % P
        x = (Lam*Lam-2*a[0]) % P
        y = (Lam*(a[0]-x)-a[1]) % P
        return(x, y)

    def eccDot(self, generatedPoint, constK):  # Double & add
        constKBin = str(bin(constK))[2:]
        Q = generatedPoint
        for i in range(1, len(constKBin)):  # EC multiplication.
            Q = self.ecTwoFold(Q)
            if constKBin[i] == "1":
                Q = self.eccAddition(Q, generatedPoint)
        return (Q)

    def gen_pubKey(self, privKey):
        PublicKey = self.eccDot(GP, privKey)
        return PublicKey

    def encryption(self, Public_Key, msg):
        msg = self.encode(msg)
        C1 = self.eccDot(GP, self.k)
        C2 = self.eccDot(Public_Key, self.k)[0] + int(msg)
        return (C1, C2)

    def decryption(self, C1, C2, private_Key):
        solution = C2 - self.eccDot(C1, private_Key)[0]
        return self.decode(str(solution))
def fileToBase64(filename):
    with open(filename, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
    return encoded_string.decode('utf-8')
def base64ToFile(encoded_string, outputFileName):
    data64decode = base64.decodebytes(encoded_string.encode('utf-8'))
    data_result = open(outputFileName, "wb")
    data_result.write(data64decode)
def makeSingleString(bigList):
    retData = ""
    dollar = "$$$$$$$$$$$$$$$$$$$$$$$$$"
    for listEle in bigList:
        msg = str(listEle)
        msg = msg + dollar
        msg = msg[0:42]
        retData = retData + msg
    return retData
def makeListFromString(longString):
    retData = []
    data = longString.split('$')
    for item in data:
        if len(item) > 0:
            retData.append(int(item))
    return retData
def encrypt(input_file):
    file_type = input_file.split(".")[1]
    multimedia_data = fileToBase64(input_file)
    print(multimedia_data[0:100])
    aes_key = 57811460909138771071931939740208549692
    # Encrypt  AES_key with ECC public key
    ecc_obj_AESkey = ECC()
    private_key = 59450895769729158456103083586342075745962357150281762902433455229297926354304
    public_key = ecc_obj_AESkey.gen_pubKey(private_key)
    (C1_aesKey, C2_aesKey) = ecc_obj_AESkey.encryption(public_key, str(aes_key))
    # Encrypt the multimedia_data with AES algorithm
    aes = AES(aes_key)
    encrypted_multimedia = aes.encryptBigData(multimedia_data)
    data_for_ecc = makeSingleString(encrypted_multimedia)
    # Encrypt the encrypted_multimedia with ECC
    ecc = ECC()
    (C1_multimedia, C2_multimedia) = ecc.encryption(public_key, data_for_ecc)
    cipher = {
        "file_type": file_type,
        "C1_aesKey": C1_aesKey,
        "C2_aesKey": C2_aesKey,
        "C1_multimedia": C1_multimedia,
        "C2_multimedia": C2_multimedia,
        "private_key": private_key
    }
    p = os.getenv('username')
    p = 'C://Users/' + p + '/Desktop/cipher.json'
    with open(p, 'w') as fp:
        json.dump(cipher, fp)
    print('Encryption Done ')
def decrypt(file):
    # file = 'cipher.json'
    with open(file) as f:
        data = json.load(f)
    C1_aesKey = data["C1_aesKey"]
    C2_aesKey = data["C2_aesKey"]
    private_key = data["private_key"]
    file_type = data["file_type"]
    # Decrypt with ECC to get the AES key
    ecc_AESkey = ECC()
    decryptedAESkey = ecc_AESkey.decryption(C1_aesKey, C2_aesKey, private_key)
    C1_multimedia = data["C1_multimedia"]
    C2_multimedia = data["C2_multimedia"]
    # Decrypt the data with ECC
    ecc_obj = ECC()
    encrypted_multimedia = ecc_obj.decryption(C1_multimedia, C2_multimedia, private_key)
    clean_data_list = makeListFromString(encrypted_multimedia)
    # Decrypt with AES
    aes_obj = AES(int(decryptedAESkey))
    decrypted_multimedia = aes_obj.decryptBigData(clean_data_list)
    # Decode from Base64 to the corresponding fileToBase64
    p = os.getenv('username')
    output_file = "C://Users/" + p + "/Desktop/Decrypted_file."+file_type
    base64ToFile(decrypted_multimedia, output_file)
    print("Decryption Done and file saved in project folder with name Decrypted_file.")


def encrypt_gui():
    def openfileE():
        p = os.getenv('username')
        filename = filedialog.askopenfilename(initialdir="C://Users/" + p + "/Desktop", title="Select file")
        print(filename)
        encrypt(filename)
        tkinter.messagebox.showinfo('Hybrid Encryption', 'Encryption process completed and cipher.json file saved in Desktop folder')
        root.destroy()
    root = tkinter.Tk()
    root.geometry("250x100+520+200")
    root.title("")
    root.resizable(False, False)
    dcl = tkinter.Label(root, text="Select a media file for encryption",font="Verdana 8 ", )
    dcl.place(x=30, y=20)
    de = tkinter.Button(root, text="Select file", command=openfileE)
    de.place(x=100, y=60)
    root.mainloop()
def decrypt_gui():
    def openfileD():
        p = os.getenv('username')
        filename = filedialog.askopenfilename(initialdir="C://Users/" + p + "/Desktop", title="Select file")
        decrypt(filename)
        tkinter.messagebox.showinfo('Hybrid Encryption','Decryption process completed and Decrypted file saved in Desktop folder')
        root.destroy()
    root = tkinter.Tk()
    root.geometry("250x100+520+200")
    root.title("")
    root.resizable(False, False)
    dcl = tkinter.Label(root, text="Select a json file for decryption", font="Verdana 8 ", )
    dcl.place(x=30, y=20)
    de = tkinter.Button(root, text="Select file", command=openfileD)
    de.place(x=100, y=60)
def gui():
    root = tkinter.Tk()
    root.geometry("300x300+500+150")
    root.title("")
    root.resizable(False, False)
    softname = Label(root, text="Hybrid Multimedia Encryption", fg="black", height=3, width=400,
                              background="white", font="Verdana 13 bold")
    softname.pack()
    enl = tkinter.Label(root, text="Click Encrypt Button to encrypt a file", fg="white", bg="#359BF6", font="Verdana 8 ", )
    enl.place(x=40, y=100)
    en=tkinter.Button(root, text="Encrypt File", command=encrypt_gui)
    en.place(x=120, y=150)
    dcl = tkinter.Label(root, text="Click Decrypt Button to Decrypt a file", fg="white", bg="#359BF6",
                        font="Verdana 8 ", )
    dcl.place(x=40, y=200)
    de = tkinter.Button(root, text="Decrypt File", command=decrypt_gui)
    de.place(x=120, y=250)
    root.mainloop()
if __name__ == "__main__":
    gui()



