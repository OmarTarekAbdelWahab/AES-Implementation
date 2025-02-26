import sys
from BitVector import *

class AES:
  def __init__(self, key):
    self.AES_modulus = BitVector(bitstring='100011011')
    self.keysize, self.key_bv = self.fix_input_key(key)
    self.round_keys = self.get_key_schedule()
    self.subBytesTable, self.invSubBytesTable = self.genTables()

  def fix_input_key(self, input_key):
    key = input_key
    keysize = 128
    key = key.strip()
    key += '0' * (keysize//8 - len(key)) if len(key) < keysize//8 else key[:keysize//8]
    key_bv = BitVector( textstring = key )
    return keysize,key_bv

  def get_key_schedule(self):
    key_words = []

    keysize, key_bv = self.keysize, self.key_bv
    key_words = self.gen_key_schedule_128(key_bv)

    key_schedule = []
    # print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())

        key_schedule.append(keyword_in_ints)
    num_rounds = None
    num_rounds = 10

    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] +
                                                       key_words[i*4+3]).get_bitvector_in_hex()
    # print("\n\nRound keys in hex (first key for input block):\n")
    # for round_key in round_keys:
    #     print(round_key)
    return round_keys

  def gee(self, keyword, round_constant, byte_sub_table):

    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
    return newword, round_constant

  def gen_key_schedule_128(self, key_bv):
    byte_sub_table = self.gen_subbytes_table()
    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(4,44):
        if i%4 == 0:
            kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-4] ^ kwd
        else:
            key_words[i] = key_words[i-4] ^ key_words[i-1]
    return key_words

  def gen_subbytes_table(self):
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

  def genTables(self):
    subBytesTable = []
    invSubBytesTable = []
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(self.AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

    return subBytesTable, invSubBytesTable
  def gmul(self, a, b):
    a = int(a)
    b = int(b)
    """Multiply two numbers in GF(2^8) using the AES modulus x^8 + x^4 + x^3 + x + 1"""
    p = 0
    for _ in range(8):
        if b & 1:  # If the least significant bit is set
            p ^= a  # XOR the product
        hi_bit_set = a & 0x80  # Check if highest bit is set
        a <<= 1  # Multiply by x (shift left)
        if hi_bit_set:  # If overflow, reduce by XOR with 0x1B
            a ^= 0x1B
        b >>= 1  # Divide b by x (shift right)
    return p & 0xFF  # Ensure result fits in a byte (8 bits)

  def key_to_matrix(self, key):
    """Converts a 16-byte key to a 4x4 matrix"""
    # print(key)
    byte_list = [BitVector(hexstring=key[i:i+2]) for i in range(0, 32, 2)]
    matrix = [[byte_list[col*4 + row] for col in range(4)] for row in range(4)]
    return matrix

  def text_to_matrix(self, text):
    byte_list = [BitVector(textstring = chr) for chr in text]
    matrix = [[byte_list[col*4 + row] for col in range(4)] for row in range(4)]
    return matrix

  def matrix_to_text(self, matrix):
    text = [matrix[row][col] for col in range(4) for row in range(4)]
    text = ''.join([chr(byte.intValue()) for byte in text])
    return text

  def add_round_key(self, state, round_key):
    """Adds the round key to the state matrix"""
    round_key = self.key_to_matrix(round_key)
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

  def sub_bytes(self, state):
    for i in range(4):
      for j in range(4):
        state[i][j] = BitVector(intVal = self.subBytesTable[state[i][j].intValue()], size = 8)
    return state

  def inv_sub_bytes(self, state):
    for i in range(4):
      for j in range(4):
        state[i][j] = BitVector(intVal = self.invSubBytesTable[state[i][j].intValue()], size = 8)
    return state

  def shift_rows(self, state):
    """Shifts the rows in the state matrix"""
    new_state = [[0] * 4 for _ in range(4)]
    for i in range(4):
        new_state[i] = state[i][i:] + state[i][:i]
    return new_state

  def inv_shift_rows(self, state):
    """Shifts the rows in the state matrix"""
    new_state = [[0] * 4 for _ in range(4)]
    for i in range(4):
        new_state[i] = state[i][-i:] + state[i][:-i]
    return new_state

  def mix_columns(self, state):
    """Applies AES MixColumns transformation to the state matrix"""
    # AES MixColumns fixed matrix
    mix_matrix = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ]

    new_state = [[0] * 4 for _ in range(4)]


    for col in range(4):  # Process each column
        for row in range(4):  # Compute new column values
            new_state[row][col] = BitVector( intVal = (
                self.gmul(mix_matrix[row][0], state[0][col]) ^
                self.gmul(mix_matrix[row][1], state[1][col]) ^
                self.gmul(mix_matrix[row][2], state[2][col]) ^
                self.gmul(mix_matrix[row][3], state[3][col])
            ), size = 8)

    return new_state

  def inv_mix_columns(self, state):
    """Applies the inverse AES MixColumns transformation"""
    # Inverse MixColumns fixed matrix
    inv_mix_matrix = [
        [0x0E, 0x0B, 0x0D, 0x09],
        [0x09, 0x0E, 0x0B, 0x0D],
        [0x0D, 0x09, 0x0E, 0x0B],
        [0x0B, 0x0D, 0x09, 0x0E]
    ]

    new_state = [[0] * 4 for _ in range(4)]

    for col in range(4):
        for row in range(4):
            new_state[row][col] = BitVector(intVal = (
                self.gmul(inv_mix_matrix[row][0], state[0][col]) ^
                self.gmul(inv_mix_matrix[row][1], state[1][col]) ^
                self.gmul(inv_mix_matrix[row][2], state[2][col]) ^
                self.gmul(inv_mix_matrix[row][3], state[3][col])
            ), size = 8)

    return new_state

  def encrypt_block(self, input_block):
    # round_keys = [BitVector(hexstring = round_key) for round_key in self.round_keys] # 11x32 chars strings (128 bits)
    round_keys = self.round_keys

    # 16 chars = 128 bits
    if len(input_block) < 16:
      input_block += '0' * (16 - len(input_block))

    state = self.text_to_matrix(input_block)

    state = self.add_round_key(state, round_keys[0])


    for i in range(1, 11):
      state = self.sub_bytes(state)
      state = self.shift_rows(state)
      if i != 10: state = self.mix_columns(state)
      state = self.add_round_key(state, round_keys[i])

    return self.matrix_to_text(state)


  def decrypt_block(self, input_block):
    # round_keys = [BitVector(hexstring = round_key) for round_key in self.round_keys] # 11x32 chars strings (128 bits)
    round_keys = self.round_keys

    # 16 chars = 128 bits
    if len(input_block) < 16:
      input_block += '0' * (16 - len(input_block))

    state = self.text_to_matrix(input_block)



    state = self.add_round_key(state, round_keys[-1])


    for i in range(9, -1, -1):
      # print("shifting...", type(state[0][0]))
      state = self.inv_shift_rows(state)
      # print("subbing...", type(state[0][0]))
      state = self.inv_sub_bytes(state)
      state = self.add_round_key(state, round_keys[i])
      if i != 0: state = self.inv_mix_columns(state)

    return self.matrix_to_text(state)

  def encrypt(self, input_text):
    if len(input_text) % 16 != 0:
      input_text += '0' * (16 - len(input_text) % 16)

    output_text = ''
    for i in range(0, len(input_text), 16):
      output_text += self.encrypt_block(input_text[i:i+16])
    return output_text

  def decrypt(self, input_text):
    if len(input_text) % 16 != 0:
      input_text += '0' * (16 - len(input_text) % 16)

    output_text = ''
    for i in range(0, len(input_text), 16):
      output_text += self.decrypt_block(input_text[i:i+16])
    return output_text
  



aes = AES(key = "abcdefghijklmnop")
enc = aes.encrypt(input_text = "You simply call this function after providing the key to get the encrypted message,\n" + 
                  "then you can use the same key to get the original message back")
print("enc:")
print(enc)
dec = aes.decrypt(input_text = enc)
print("dec:")
print(dec)