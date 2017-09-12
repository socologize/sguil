#!/usr/bin/python

import sys
import requests
import json

container = {"label": "network"}
artifact = {"label": "event"}
raw_data = []
raw_data1 = []
host = []
url = []
cef = {}
count = 0

PHANTOM_IP = "x.x.x.x"
VERIFY = False
PHANTOM_BASE_URL = "https://{0}/".format(PHANTOM_IP)
AUTH_HEADER = {
  "ph-auth-token": "< your auth token here>",
  "server": "https://x.x.x.x"
}

if len(sys.argv) == 2:
    with open('tmp.txt','w') as temp:
        temp.write(sys.argv[1])
        temp.write('\r\n')
        temp.close()
	print "****** Script start parse raw data"
    with open(sys.argv[1],'r') as transcript:
        for line in transcript:
	    raw_data.append(line)
	    if "Timestamp:" in line:
                start_time = line.split('p')[1].strip(': \t\n')
                start_time = start_time.replace(' ','T') + "Z"
                container["start_time"] = start_time 
            elif "Connection ID:" in line:
                container["source_data_identifier"] = line.split(':')[1].strip('\t\n')
                container["description"] = line.split(':')[1].strip(' \t\n')
                container["name"] = line.split(':')[1].strip('. \t\n')
            elif "Src IP:" in line:
                cef["sourceAddress"] = line.split(':')[1].strip(' \t\n')
            elif "Dst IP" in line:
                cef["destinationAddress"] = line.split(':')[1].strip(' \t\n')
            elif "Src Port:" in line:
                cef["sourcePort"] = line.split(':')[1].strip(' \t\n')
            elif "Dst Port" in line:
                cef["destinationPort"] = line.split(':')[1].strip(' \t\n')
            elif "Event Message:" in line:
                cef["message"] = line.split(':')[1].strip(' \t\n')
	    elif "AlertID:" in line:
		artifact["source_data_identifier"] = line.split(':')[1].strip(' \t\n')
	        cef["deviceExternalId"] = line.split(':')[1].strip(' \t\n')
	    elif "Count:" in line: 
		cef["baseEventCount"] = line.split(':')[1].strip(' \t\n')          
            elif "---Event---" in line:
		artifact = {"name":"SGUIL Alert {0}".format(cef["deviceExternalId"]),"type": "transcript"}   
    		container["data"] = ''.join(raw_data)
    		container_url = PHANTOM_BASE_URL + "rest/container"
    		container_resp = requests.post(container_url, headers=AUTH_HEADER, data=json.dumps(container), verify=VERIFY) #save container
    		artifact["container_id"] = container_resp.json()["id"]
    		artifact["cef"] = cef
   		artifact_url = PHANTOM_BASE_URL + "rest/artifact"
    		artifact_resp = requests.post(artifact_url, headers=AUTH_HEADER, data=json.dumps(artifact), verify=VERIFY) # save artifact
	    else:
                pass	    
    transcript.close()
