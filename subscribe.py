import argparse
import time
import requests
import json
import hashlib
import paho.mqtt.subscribe as subscribe
from base64 import b64decode
from Crypto.Cipher import AES
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.core.engine.util import bytesToObject

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--topic", required=True, type=str)
parser.add_argument("-H", "--hostname", nargs="?", default="localhost", type=str)
parser.add_argument("-at", "--attributes", nargs="?", required=True, type=str)
parser.add_argument( "-id", "--client_id", type=str)
args = parser.parse_args()

topic = args.topic
hostname = args.hostname
attributes = args.attributes
client_id = args.client_id

group = PairingGroup("SS512")
cpabe = CPabe09(group)

parameters = ""
attributes_list = attributes.split()
for i, attribute in enumerate(attributes_list):
    parameters += "a[{}]={}&".format(i, attribute.upper())

pk = bytesToObject(
        requests.get("http://{}:{}/public_key"
        .format(hostname, "8000")).content,
        group)

sk = bytesToObject(
        requests.get("http://{}:{}/secret_key?{}"
        .format(hostname, "8000", parameters)).content,
        group)

print("{} subscribed to {} in {}".format(time.asctime(), topic, hostname))

encrypted_payload = bytesToObject(
        subscribe.simple(topic, hostname=hostname, client_id=client_id).payload,
        group)

encrypted_aes_key = encrypted_payload['encrypted_aes_key']
encrypted_data = encrypted_payload['encrypted_data']

el = cpabe.decrypt(pk, sk, encrypted_aes_key)
key = hashlib.md5(str(el).encode()).digest()

b64 = json.loads(encrypted_data)
json_k = [ "nonce", "ciphertext", "tag" ]
jv = { k:b64decode(b64[k]) for k in json_k }

cipher = AES.new(key, AES.MODE_EAX, nonce=jv['nonce'])
plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag']).decode()

print("--------------------------------------------------------------------------------")
print(time.asctime())
print("{:15} {}".format("topic:", topic))
print("{:15} {}".format("payload:", plaintext))
print("{:15} {}".format("hostname:", hostname))
print("{:15} {}".format("attributes", attributes))
print("--------------------------------------------------------------------------------")
