from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.core.engine.util import objectToBytes

PORT = 8000
group = PairingGroup("SS512")
cpabe = CPabe09(group)
(mk, pk) = cpabe.setup()

class HandleRequests(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = parse.urlsplit(self.path)
        params = dict(parse.parse_qsl(parsed_url.query))

        if parsed_url.path == "/public_key":
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(objectToBytes(pk, group))

        if parsed_url.path == "/secret_key":
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            attributes = list(params.values())
            sk = cpabe.keygen(pk, mk, attributes)
            self.wfile.write(objectToBytes(sk, group))

server_address = ("", PORT)
httpd = HTTPServer(server_address, HandleRequests)
print("Serving at port {}".format(PORT))
httpd.serve_forever()
