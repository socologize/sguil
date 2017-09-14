
#!/usr/bin/env python
#
# SaveAs plugin script that pushes REST JSON formatted objects to
# the Phantom Security Automation and Orchestration platform
# works for Community version and from 2.1 to 3.x
#
# by Rob Gresham @SOCologize / Phantom Cyber with contributions from Tim Frazier

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
  "ph-auth-token": "<your auth token here>",
  "server": "https://1x.x.x.x"
}

if len(sys.argv) == 2:
    with open('tmp.txt','w') as temp:
        temp.write(sys.argv[1])
        temp.write('\r\n')
        temp.close()
	print "****** Script start parse raw data"
    with open(sys.argv[1],'r') as transcript:
	artifact = {"name":"IP Transcript","type": "transcript"}
        for line in transcript:
	    raw_data.append(line)
            if "Timestamp:" in line:
                start_time = line.split('p')[1].strip(': \t\n')
                start_time = start_time.replace(' ','T') + "Z"
                container["start_time"] = start_time 
            elif "Connection ID:" in line:
                container["source_data_identifier"] = line.split('_')[1].strip('\t\n')
                artifact["source_data_identifier"] = line.split('_')[1].strip(' \t\n')
                container["description"] = "IP transcript for " + line.split(':')[1].strip(' \t\n')
                container["name"] = "Transcript " + line.split(':')[1].strip('. \t\n')
            elif "Src IP:" in line:
                cef["sourceAddress"] = line.split(':')[1].split('(')[0].strip(' \t\n')
		cef["sourceDnsDomain"] = line.split(':')[1].split('(')[1].strip(') \t\n')
            elif "Dst IP" in line:
                cef["destinationAddress"] = line.split(':')[1].split('(')[0].strip(' \t\n')
		cef["destinationHostName"] = line.split(':')[1].split('(')[1].strip(') \t\n')
            elif "Src Port:" in line:
                cef["sourcePort"] = line.split(':')[1].strip(' \t\n')
            elif "Dst Port" in line:
                cef["destinationPort"] = line.split(':')[1].strip(' \t\n')
            elif "OS Fingerprint:" in line:
                pass
	    elif "SRC:" in line:
		raw_data1 += line		
		if count == 0:
		    cef["requestMethod"] = line.split(' ')[1].strip(' \t\n')
		    url = line.split(' ')[2].strip(' \t\n')
		    #print url
		elif "SRC: Host:" in line:
	            host = line.split(' ')[2].strip(' \t\n')
		    cef["destinationDnsDomain"] = line.split(' ')[2].strip(' \t\n')
		    #print host
		else:
		    pass
		count += 1
	    elif "DST:" in line:
		raw_data1 += line 
            else:
                pass	    

    transcript.close()
    print "****Constructs*****"
    cef["fullRequestURL"] = 'http://{0}{1}'.format(host,url)
    #print cef["fullRequestURL"] 
    #cef["deviceCustomString1"] = ''.join(raw_data1)
    #cef["deviceCustomString1Label"] = 'Request Transcript'
    #print cef["deviceCustomString1"] 
    print ""   
    container["data"] = ''.join(raw_data)
    container_url = PHANTOM_BASE_URL + "rest/container"
    # debug 
    #print container
    container_resp = requests.post(container_url, headers=AUTH_HEADER, data=json.dumps(container), verify=VERIFY) #save container
    print "****CONTAINER RESPOSE*****"
    print container_resp.json()
    print ""
    # get container id
    artifact["container_id"] = container_resp.json()["id"]
    artifact["cef"] = cef
    print "****ARTIFACT Success*****"
    #print artifact
    print ""
    artifact_url = PHANTOM_BASE_URL + "rest/artifact"
    artifact_resp = requests.post(artifact_url, headers=AUTH_HEADER, data=json.dumps(artifact), verify=VERIFY) # save artifact
