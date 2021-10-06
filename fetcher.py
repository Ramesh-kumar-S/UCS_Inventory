from json.decoder import JSONDecodeError
import requests
from requests.api import get
requests.urllib3.disable_warnings()
from xml.etree import cElementTree as ET
from xml.dom import minidom
import pandas as pd
from tabulate import tabulate
import json
import argparse
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import Requester
import textwrap

D={}

parser = argparse.ArgumentParser(
        prog='Cisco UCS Automation : ',
        description="This Cisco UCS Script will let's you to Fetch Equipment information from UCS Manager via XML API and Display the Searched Component details in a User Friendly Tabular Format.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
         Additional information:
         ''')
    )
parser.add_argument('--getAdaptors',nargs='?',default="defi",help="An Optional String that will list all the adapters in a Setup ,If Specific Adapter Model is Not Specified.",metavar="")
parser.add_argument('--getBladeServers',nargs='?',default="defi",help="An Optional Parameter that will Fetch all the Blade Servers If not Specified an Appropriate Model",metavar="")
parser.add_argument('--getRackServers',nargs='?',default="defi",help="An Optional Parameter that will Fetch all the Rack Mount Servers If not Specified an Appropriate Model",metavar="")
parser.add_argument('--getControllers',nargs='?',default="defi",help="An Optional Parameter that will Fetch all the Board Controllers If not Specified an Appropriate Model",metavar="")
parser.add_argument('--getFIs',nargs='?',default="defi",help="An Optional parameter that will fetch all the Fabric Interconnect(FI) Details",metavar="")
parser.add_argument('--getDisks',nargs='?',default="defi",help="An Optional Parameter that will Fetch all the Storage Controllers Disks If not Specified an Appropriate Model",metavar="")
# parser.print_help()
args = parser.parse_args()

def FETCHER(IPaddr,Uname,Passwd):
    
    """  
    Usually when Dealing with Request's , Intrepreter Might Raise warning about Insecure Connection Request, In order to Resolve thiis warning and Make most user friendly script we must ignore this Warning using the Following snippet ! 
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    # global IP
    IP_Addr=IPaddr   #input("\nEnter the Setup IP : ")
    IP=IP_Addr.strip().split('/')[-1] 
    USERNAME=Uname #input("\nEnter the Username :") #"ucspe"#input("Enter the Username :") 
    PASSWORD=Passwd #getpass.getpass(prompt='\nEnter your Password : ', stream=None) #"ucspe"#getpass.getpass(prompt='Enter your Password : ', stream=None)
    """
    XML_ALTERNATOR Function takes XML_CODE as an Argument and Makes Request to the Specified IP Using POST Requests Library and Return XML_Response Code
    """
    def XML_ALTERNATOR(Response):
        Login_Response = Response
        XML_Element_Tree = ET.fromstring(Login_Response)
        COOKIE=XML_Element_Tree.attrib['outCookie']
        configResolveClass_Server_Query ='<configResolveClasses cookie="1617209698/8bf08bee-8e3c-463a-bb7a-b51c59545cf0" inHierarchical="true"> <inIds> <Id value="computeItem"/> <Id value="computeRackUnit" /> </inIds> </configResolveClasses>'
        DOM = minidom.parseString(configResolveClass_Server_Query)
        ELEMENT = DOM.getElementsByTagName('configResolveClasses')
        ELEMENT[0].setAttribute('cookie', COOKIE)
        CONFIG_QUERY_WITH_NEW_COOKIE=DOM.toprettyxml(indent='    ')
        return CONFIG_QUERY_WITH_NEW_COOKIE
    """
    FI_FETCHER Function takes Response Returned from XML_ALTERNATOR Function Which Mainly Replaces the New Response Cookie Returned from UCS Login Request
    """
    def FI_FETCHER(Response):
        Login_Response = Response
        XML_Element_Tree = ET.fromstring(Login_Response)
        COOKIE=XML_Element_Tree.attrib['outCookie']
        configResolveClass_FI_Query='<configResolveClasses cookie="1619182011/9a5812e8-3bf5-4565-b027-b450668a12e6" inHierarchical="true"> <inIds> <Id value="computeItem"/> <Id value="networkElement" /> </inIds> </configResolveClasses>'
        DOM1 = minidom.parseString(configResolveClass_FI_Query)
        ELEMENT1 = DOM1.getElementsByTagName('configResolveClasses')
        ELEMENT1[0].setAttribute('cookie', COOKIE)
        FI_CONFIG_QUERY_WITH_NEW_COOKIE=DOM1.toprettyxml(indent='    ')
        return FI_CONFIG_QUERY_WITH_NEW_COOKIE

    """Login Request XML Code"""
    try:
        Login_Query=f'<aaaLogin inName= {USERNAME} inPassword= {PASSWORD} ></aaaLogin>'
        Login_Response = Requester.REQUESTER(Login_Query,IP)
        Config_Response=Requester.REQUESTER(XML_ALTERNATOR(Login_Response),IP)
        Fi_Response=Requester.REQUESTER(FI_FETCHER(Login_Response),IP)
        Server_ElementTree=ET.ElementTree(ET.fromstring(Config_Response))
        FI_ElementTree=ET.ElementTree(ET.fromstring(Fi_Response))
    except requests.exceptions.RequestException:
        print("\n Incorrect IP or Connection Error \n")
        print("\n Check your IP or Credentials/Try Again!! \n")
        quit()
    SERVERS={}
    FI={}
    DUP=[]
    FI_counter=0
    counter=0
    """
    This Section of Code Extracts the Specific Fabric Interconnect Attributes from the ConfigResolveClasses XML Response and Save's in the Nested Dictionary Format
    """
    for node in FI_ElementTree.findall('.//outConfigs/'):
        FI_counter += 1
        if node.tag=="networkElement":
            FI[FI_counter]={
                                "UCS IP":IP,
                                "FI Name":node.attrib['dn'],
                                "FI Model":node.attrib['model'],
                                "FI Serial":node.attrib['serial'],
                                "IP Address":node.attrib['oobIfIp'],
                                "Subnet Mask":node.attrib['oobIfMask'],
                                "Default Gateway":node.attrib['oobIfGw']
                         }
        else:
            break
    
    def Adapters():
        ADAPTERS={}
        c=0
        for node in Server_ElementTree.findall('.//outConfigs/*'):
            for adapter in node.findall('.//adaptorUnit'):
                if node.tag=="computeBlade":  
                    ADAPTERS[c]= {      "Setup IP":IP_Addr,
                                        "Server ID" : node.attrib["serverId"],                     
                                        "Adapter ID":adapter.attrib['id'],
                                        "Adapter Model":adapter.attrib['model'],
                                        "Adapter Serial":adapter.attrib['serial'],
                                        "Adapter Vendor":adapter.attrib['vendor']  
                                }
                    c+=1
        Adaps={"Adapters":ADAPTERS}
        D[IP_Addr]=Adaps
        # if query!="defi":
        #     for k,v in ADAPTERS.items():
        #         for v1,v2 in v.items():
        #             if query in v2:
        #                 print(v)
        # print(json.dumps(ADAPTERS,indent=4))

    def Blades():
        BLADES={}
        c=0
        for node in Server_ElementTree.findall('.//outConfigs/*'):
            if node.tag=="computeBlade":
                BLADES[c]={   

                               "Server ID":node.attrib['serverId'],
                               "Server Type": "Blade Server",
                               "Chassis ID":node.attrib['chassisId'],
                               "Blade Slot ID":node.attrib['slotId'],
                               "Blade Model":node.attrib['model'],
                               "Blade Serial":node.attrib['serial'],
                               "No of Adaptors":node.attrib['numOfAdaptors']
                          }
                c+=1
        Blades={"Blades":BLADES}
        D[IP_Addr].update(Blades)


    def Racks():
        c=0
        DUP=[]
        RACKS={}
        for node in Server_ElementTree.findall('.//outConfigs/*'):
            if node.tag=="computeRackUnit" and node.attrib['serial'] not in DUP: 
                RACKS[c]={
                            "Setup IP":IP_Addr,
                            "Server Type":"".join(["Rack Server" if node.tag=="computeRackUnit" else "Blade Server"]),
                            "Server ID":node.attrib['serverId'],
                            "Server Type": "Rack Server",
                            "Model" : node.attrib['model'],
                            "Serial" : node.attrib['serial'],
                            "Adapter's" : node.attrib['numOfAdaptors']
                        }
                c+=1
        Racks={"Racks":RACKS}
        D[IP_Addr].update(Racks)

    def Fi():
        Fi={"Fi":FI}
        D[IP_Addr].update(Fi)

    def Controllers():
        CONTROLLERS={}
        c=0
        for node in Server_ElementTree.findall('.//outConfigs/*'):
            for controller in node.findall('.//computeBoard/storageController'):
                disks=[disk for disk in node.findall('.//storageLocalDisk')]
                CONTROLLERS[c]={
                                "Setup IP":IP_Addr,
                                "Server ID":node.attrib['serverId'],
                                "Server Type":"".join(["Rack Server" if node.tag=="computeRackUnit" else "Blade Server"]),
                                "S Controller ID":controller.attrib['id'],
                                "S Controller Name":controller.attrib['rn'],
                                "S Controller Type":controller.attrib['type'],
                                "S Controller Model":controller.attrib['model'],
                                "S Controller Serial":controller.attrib['serial'],
                                "S Controller Vendor":controller.attrib['vendor'],
                                "No of Disks Present":len(disks)
                            }
                c+=1
        Controllers={"Controllers":CONTROLLERS}
        D[IP_Addr].update(Controllers)
    
    def Disks():
        DISKS={}
        c=0
        for node in Server_ElementTree.findall('.//outConfigs/*'):
            for disk in node.findall('.//computeBoard/storageController/storageLocalDisk'):
                DISKS[c]={
                         "Setup IP":IP_Addr,
                         "Server ID":node.attrib['serverId'],
                         "Server Type":"".join(["Rack Server" if node.tag=="computeRackUnit" else "Blade Server"]),
                         "Disk ID":disk.attrib['id'],
                         "Disk Type":disk.attrib['deviceType'],
                         "Disk Serial":disk.attrib['serial'],
                         "Disk Vendor":disk.attrib['vendor'],
                         "Disk Speed":disk.attrib['linkSpeed'],
                         "Disk State":disk.attrib['diskState']
                       }
                c+=1
        Disks={"Disks":DISKS}
        D[IP_Addr].update(Disks)
        

    Adapters()
    Fi()
    Racks()
    Blades()
    Controllers()
    Disks()

# Ips=["10.106.189.140","10.127.56.66"]
# for i in Ips:
#     FETCHER(i,"admin","Nbv12345")
with open("config.json","r") as f:
    data=json.load(f)
for x in data.values():
    FETCHER(x[0],x[1],x[2])
def printer(data):
    df = pd.DataFrame.from_dict(data,orient='index')
    print(tabulate(df,tablefmt='fancy_grid'))

if args.getAdaptors!="defi":
    for k,v in D.items():
        for v1,v2 in v.items():
            if v1=="Adapters":
                for vv1,vv2 in v2.items():
                    for x1,x2 in vv2.items():
                        if args.getAdaptors in x2:
                            printer(vv2)
                        else:
                            print("Adapter Not Available in Any Setup")


if args.getBladeServers!="defi":
    for k,v in D.items():
        for v1,v2 in v.items():
            if v1=="Blades":
                for vv1,vv2 in v2.items():
                    for x1,x2 in vv2.items():
                        if args.getBladeServers in x2:
                            printer(vv2)
                        else:
                            print("Unavailable")

if args.getRackServers!="defi":
    for k,v in D.items():
        for v1,v2 in v.items():
            if v1=="Racks":
                for vv1,vv2 in v2.items():
                    for x1,x2 in vv2.items():
                        if args.getRackServers in x2:
                            printer(vv2)
                        else:
                            print("Unavailable")

if args.getControllers!="defi":
    for k,v in D.items():
        for v1,v2 in v.items():
            if v1=="Controllers":
                for vv1,vv2 in v2.items():
                    for x1,x2 in vv2.items():
                        if args.getControllers in x2:
                            printer(vv2)
                        else:
                            print("Unavailable")
if args.getFIs!="defi":
    for k,v in D.items():
        for v1,v2 in v.items():
            if v1=="Fi":
                for vv1,vv2 in v2.items():
                    for x1,x2 in vv2.items():
                        if args.getFIs in x2:
                            printer(vv2)
                        else:
                            print("Unavailable")
if args.getDisks!="defi":
    for k,v in D.items():
        for v1,v2 in v.items():
            if v1=="Disks":
                for vv1,vv2 in v2.items():
                    for x1,x2 in vv2.items():
                        if args.getDisks in x2:
                            printer(vv2)
                        else:
                            print("Unavailable")