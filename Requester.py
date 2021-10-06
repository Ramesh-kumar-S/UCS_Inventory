import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


"""
The Requestor is a Function that takes XML CODE as a argument , makes a Request to the user Specified IP and Return the Response from the Server in the form of XML Format 
"""
def REQUESTER(xml_code,IP):
    payload=xml_code
    URL="https://{}/nuova".format(IP)
    headers={'Content-Type': 'application/xml'}
    Response_data=requests.post(URL,data=payload,headers=headers,verify=False)
    return Response_data.text
