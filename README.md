#写在之前
项目中用到的函数简介：https://github.com/EveandBob/Introduction-to-some-functions-in-elliptic-curves-not-projects-

# 项目名称
PGP协议的实现

# 项目实现
PGP协议的描述如下：

发送方
![Screenshot 2022-07-31 132154](https://user-images.githubusercontent.com/104854836/182011435-913efca7-0313-4202-a279-9ca1f6fc3aea.jpg)

 1 对明文邮件 X 进行 MD5 运算，得出 MD5 报文摘要 H。用 A 的私钥对 H 进行加密（即数字签名），得出报文鉴别码 MAC（即sig(H(M))），把它拼接在明文 X 后面，得到扩展的邮件 X || MAC。

补：对该发送的消息进行压缩，记为Z(sig(H(M)) ||M)；

2 使用 A 自己生成的一次性密钥Ks对扩展的邮件X || MAC进行加密。

3 用 B 的公钥对 A 生成的一次性密钥进行加密，即EB公钥(Ks)。因为加密所用的密钥是一次性的，即密钥只会使用一次，不会出现因为密钥泄露导致之前的加密内容被解密。即使密钥被泄露了，也只会影响一次通信过程。

4 把加了密的一次性密钥和加了密的扩展的邮件连接（即EB公钥(Ks) ||EKs(Z(sig(H(M)) ||M))）发送给 B。

接收方
![Screenshot 2022-07-31 132309](https://user-images.githubusercontent.com/104854836/182011477-2b8267ea-202f-4286-a021-09fd8d7c84cb.jpg)

1) 把被加密的一次性密钥EB公钥(Ks)和被加密的扩展报文X || MAC分离开。

2) 用 B 自己的私钥解出 A 的一次性密钥Ks。

3) 用解出的一次性密钥Ks对报文进行解密，然后分离出明文 X 和MAC。

4) 用 A 的公钥对 MAC 进行解密（即签名核实），得出报文摘要 H。这个报文摘要就是 A 原先用明文邮件 X 通过 MD5 运算生成的那个报文摘要。

5) 对签名进行验证：对分离出的明文邮件 X 进行 MD5 报文摘要运算，得出另一个报文摘要 H(X)。把 H(X) 和前面得出的 H 进行比较，是否和一样。如一样，则对邮件的发送方的鉴别就通过了，报文的完整性也得到肯定。

# 部分代码
```python
def PGP():
    key = b'3l5butlj26hvv313'
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    crypt_sm4 = sm4.CryptSM4()
    dA,PA=get_key()
    dB, PB = get_key()
    IDA=12345
    IDB=54321
    msg = "encryption standard"
    #print(sm3_sign(msg,IDA,dA,PA))
    encrypt_value=0
    encrypt_key=0
    def PGP_sent(msg):
        nonlocal encrypt_value,encrypt_key
        H=sm3.sm3_hash(list(msg.encode()))
        temp=str(sm3_sign(H,IDA,dA,PA))
        #print(temp)
        MAC=(temp+msg).encode()
        #print(MAC)
        crypt_sm4.set_key(key, SM4_ENCRYPT)
        encrypt_value = crypt_sm4.crypt_ecb(MAC)
        #print(encrypt_value)# bytes类型
        crypt_sm4.set_key(key, SM4_DECRYPT)
        MAC = crypt_sm4.crypt_ecb(encrypt_value)
        #print(MAC)
        encrypt_value=bytes_to_int(encrypt_value)
        encrypt_key=sm3_en(key.decode(),PB)
        encrypt_key=bytes_to_int(str(encrypt_key).encode())
        return encrypt_value,encrypt_key

    def PGP_get(encrypt_value,encrypt_key):
        encrypt_key=int_to_bytes(encrypt_key)
        encrypt_key=json.loads(encrypt_key.decode())
        key=sm3_de(encrypt_key,dB).encode()
        encrypt_value = int_to_bytes(encrypt_value)
        crypt_sm4.set_key(key, SM4_DECRYPT)
        MAC = crypt_sm4.crypt_ecb(encrypt_value)
        MAC=MAC.decode()
        result = re.match("\[.*\]", MAC)
        sign=json.loads(result.group())
        msg_for_get=MAC[MAC.find(']')+1:]
        print("解密出的消息为: "+msg_for_get)
        H = sm3.sm3_hash(list(msg_for_get.encode()))
        print(verif_sign(H, sign, IDA, PA))
    print("加密消息为"+msg)
    print("发送方的消息：")
    print(PGP_sent(msg))
    PGP_get(encrypt_value,encrypt_key)
```

# 实现结果
![Screenshot 2022-07-31 132735](https://user-images.githubusercontent.com/104854836/182011632-770dba12-7256-4e3e-a6bc-0f4653ad9261.jpg)





