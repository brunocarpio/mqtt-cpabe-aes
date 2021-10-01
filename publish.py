import argparse
import time
import hashlib
import requests
import json
from base64 import b64encode
from Crypto.Cipher import AES
import paho.mqtt.publish as publish
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.core.engine.util import objectToBytes, bytesToObject

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--topic", required=True, type=str)
parser.add_argument("-p", "--payload", nargs="?", default="")
parser.add_argument("-H", "--hostname", nargs="?", default="localhost", type=str)
parser.add_argument("-ap", "--access_policy", nargs="?", required=True, type=str)
parser.add_argument( "-id", "--client_id", type=str)
args = parser.parse_args()

topic = args.topic
payload = args.payload
hostname = args.hostname
access_policy = args.access_policy
client_id = args.client_id

group = PairingGroup("SS512")
cpabe = CPabe09(group)
el = group.random(GT)

PORT = 8000

pk = bytesToObject(
        requests.get("http://{}:{}/public_key"
        .format(hostname, PORT)).content,
        group)

encrypted_aes_key = cpabe.encrypt(pk, el, access_policy)

key = hashlib.md5(str(el).encode()).digest()
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(payload.encode())

json_k = [ 'nonce', 'ciphertext', 'tag' ]
json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, ciphertext, tag) ]
encrypted_data = json.dumps(dict(zip(json_k, json_v)))

encrypted_payload = { "encrypted_aes_key": encrypted_aes_key, "encrypted_data": encrypted_data }

publish.single(topic, payload=objectToBytes(encrypted_payload, group), hostname=hostname, client_id=client_id)
print("--------------------------------------------------------------------------------")
print(time.asctime())
print("{:15} {}".format("topic:", topic))
print("{:15} {}".format("payload:", payload))
print("{:15} {}".format("hostname:", hostname))
print("{:15} {}".format("access policy:", access_policy))
print("--------------------------------------------------------------------------------")
