from __future__ import print_function

import datetime
import time

from numpy import *

import sys
import json
import requests

import urllib3
urllib3.disable_warnings()
# System Access Global Variables!
server = None
domain_uuid = None
global urlReq
urlReq = 1

def setSysAccess():
    username = 'xxxxxx'
    if len(sys.argv) > 1:
        username = sys.argv[1]

    password = 'xxxxxxxx'
    if len(sys.argv) > 2:
        password = sys.argv[2]

    global server
    global domain_uuid

    server = "xxxxxxxx"
    domain_uuid = "e276abec-e0f2-11e3-8169-6d9ed49b625f"

    r = None
    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
    try:
        # 2 ways of making a REST call are provided:
        # One with "SSL verification turned off" and the other with "SSL verification turned on".
        # The one with "SSL verification turned off" is commented out. If you like to use that then
        # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
        # REST call with SSL verification turned off:
        # r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        # REST call with SSL verification turned on: Download SSL certificates from your FMC first and provide its path for verification.
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password), verify=False)

        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        print('Auth Token: ', auth_token)
        if auth_token is None:
            print("auth_token not found. Exiting...")
            sys.exit()
    except Exception as err:
        print("Error in generating auth token --> " + str(err))
        sys.exit()
    return auth_token


def getAccessPolicy(auth_token, api_function, container_uuid, api_subfunction, tag):
    global urlReq
    if urlReq >= 119:
        time.sleep(65)
        urlReq = 1
    entryBuilder = []
    headers = {'Content-Type': 'application/json', 'X-auth-access-token': auth_token}
    api_path = "/api/fmc_config/v1/domain/" + domain_uuid + api_function + container_uuid + api_subfunction  # param
    url = server + api_path + '?offset=0&limit=1000'
    if url[-1] == '/':
        url = url[:-1]

    try:
        # REST call with SSL verification turned off:
        # r = requests.get(url, headers=headers, verify=False)
        # REST call with SSL verification turned on:
        reqRes = requests.get(url, headers=headers, verify=False)
        urlReq += 1
        status_code = reqRes.status_code
        resp = reqRes.text
        if status_code is 200:
            print("GET successful. Response data --> Container: ", container_uuid)
            json_resp = json.loads(resp)
        else:
            reqRes.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if reqRes: reqRes.close()
    if 'items' in json_resp:
        for element in json_resp['items']:
            policyPair = [tag, container_uuid, element['id'], element['name']]
            entryBuilder.append(policyPair)

    return entryBuilder


def getACLDetails(auth_token, api_function, container_uuid, api_subfunction, object_uuid, tag):
    global urlReq
    if urlReq >= 119:
        time.sleep(65)
        urlReq = 1
    entryBuilder = []
    headers = {'Content-Type': 'application/json', 'X-auth-access-token': auth_token}
    api_path = "/api/fmc_config/v1/domain/" + domain_uuid + api_function + container_uuid + api_subfunction + object_uuid
    url = server + api_path
    if url[-1] == '/':
        url = url[:-1]

    try:
        # REST call with SSL verification turned off:
        # r = requests.get(url, headers=headers, verify=False)
        # REST call with SSL verification turned on:
        reqRes = requests.get(url, headers=headers, verify=False)
        urlReq += 1
        status_code = reqRes.status_code
        resp = reqRes.text


        if status_code is 200:
            print("GET successful. Response data --> Object UUID", object_uuid)
            json_resp = json.loads(resp)
        else:
            reqRes.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if reqRes: reqRes.close()
    if status_code == 429:
        time.sleep(65)
        urlReq = 1
        try:
            # REST call with SSL verification turned off:
            # r = requests.get(url, headers=headers, verify=False)
            # REST call with SSL verification turned on:
            reqRes = requests.get(url, headers=headers, verify=False)
            urlReq = 1
            status_code = reqRes.status_code
            resp = reqRes.text


            if status_code is 200:
                print("GET successful. Response data --> Object UUID", object_uuid)
                json_resp = json.loads(resp)
            else:
                reqRes.raise_for_status()
                print("Error occurred in GET --> " + resp)
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        finally:
            if reqRes: reqRes.close()

    if status_code == 404:
        return None
    userList = []
    if 'users' in json_resp:
        userElement = json_resp['users']
        for element in userElement['objects']:
            pairingList = [element['type'], element['name']]
            userList.append(pairingList)

    urlList = []
    if 'urls' in json_resp:
        urlElement = json_resp['urls']
        if 'literals' in urlElement:
            for element in urlElement['literals']:
                pairingList = [element['type'], element['url']]
                urlList.append(pairingList)
        # for element in urlElement['urlCategoriesWithReputation']:
        #     pairingList = [element['type'], element['url']]
        #     urlList.append(pairingList)

    srcZoneList = []
    if 'sourceZones' in json_resp:
        srcZoneElement = json_resp['sourceZones']
        for element in srcZoneElement['objects']:
            pairingList = [element['type'], element['name']]
            srcZoneList.append(pairingList)

    dstZoneList = []
    if 'destinationZones' in json_resp:
        dstZoneElement = json_resp['destinationZones']
        for element in dstZoneElement['objects']:
            pairingList = [element['type'], element['name']]
            dstZoneList.append(pairingList)

    srcNetList = []
    if 'sourceNetworks' in json_resp:
        srcNetElement = json_resp['sourceNetworks']
        if 'literals' in srcNetElement:
            for element in srcNetElement['literals']:
                pairingList = [element['type'], element['value']]
                srcNetList.append(pairingList)
        if 'objects' in srcNetElement:
            for element in srcNetElement['objects']:
                pairingList = [element['type'], element['name']]
                srcNetList.append(pairingList)

    dstNetList = []
    if 'destinationNetworks' in json_resp:
        dstNetElement = json_resp['destinationNetworks']
        if 'literals' in dstNetElement:
            for element in dstNetElement['literals']:
                pairingList = [element['type'], element['value']]
                dstNetList.append(pairingList)
        if 'objects' in dstNetElement:
            for element in dstNetElement['objects']:
                pairingList = [element['type'], element['name']]
                dstNetList.append(pairingList)

    srcPrtList = []
    if 'sourcePorts' in json_resp:
        srcPrtElement = json_resp['sourcePorts']
        if 'literals' in srcPrtElement:
            for element in srcPrtElement['literals']:
                    pairingList = [element['protocol'], element['port']]
                    srcPrtList.append(pairingList)
        if 'objects' in srcPrtElement:
                for element in srcPrtElement['objects']:
                    pairingList = [element['type'], element['name']]
                    srcPrtList.append(pairingList)

    dstPrtList = []
    if 'destinationPorts' in json_resp:
        dstPrtElement = json_resp['destinationPorts']
        if 'literals' in dstPrtElement:
            for element in dstPrtElement['literals']:
                pairingList = [element['protocol'], element['port']]
                dstPrtList.append(pairingList)
        if 'objects' in dstPrtElement:
                for element in dstPrtElement['objects']:
                    pairingList = [element['type'], element['name']]
                    dstPrtList.append(pairingList)

    appsList = []
    if 'applications' in json_resp:
        appsElement = json_resp['applications']
        if 'catagories' in appsElement:
            for element in appsElement['categories']:
                pairingList = [element['type'], element['name']]
                appsList.append(pairingList)
        if 'applications' in appsElement:
            for element in appsElement['applications']:
                pairingList = [element['type'], element['name']]
                appsList.append(pairingList)

    return [tag, container_uuid, json_resp['name'], json_resp['action'], srcZoneList, dstZoneList, srcNetList,
            dstNetList, srcPrtList, dstPrtList, userList, urlList, appsList, json_resp['enabled']]

def processedACLEntries():

    processedText = 'Enabled\tPolicy Name\tPolicy ID\tRule Name\tAction\tSource Zone\tDestination Zone\tSource Network\tDestination Network\tSource Port\tDestination Port\tUsers\tURL\tApplication\n'
    for element in aclDetails:
        processedText += str(element[13]) + '\t'
        processedText += str(element[0]) + '\t'
        processedText += str(element[1]) + '\t'
        processedText += str(element[2]) + '\t'
        processedText += str(element[3]) + '\t'
        for component in element[4]:
            processedText += str(component[1]) + ','
        processedText += '\t'
        for component in element[5]:
            processedText += str(component[1]) + ','
        processedText += "\t"
        for component in element[6]:
            processedText += str(component[1]) + ','
        processedText += "\t"
        for component in element[7]:
            processedText += str(component[1]) + ','
        processedText += "\t"
        for component in element[8]:
            processedText += str(component[1]) + ','
        processedText += "\t"
        for component in element[9]:
            processedText += str(component[1]) + ','
        processedText += "\t"
        for component in element[10]:
            processedText += str(component[1]) + ','
        processedText += "\t"
        for component in element[11]:
            processedText += str(component[1]) + ','
        processedText += "\t"
        for component in element[12]:
            processedText += str(component[1]) + ','
        processedText += "\n"

    return processedText



def writeFile():
    fileLocation = 'c:\\'
    todaysDate = datetime.date
    fileName = 'FirewallReviews' + str(todaysDate.today()) + '.txt'
    reportFile = open(fileName, "+w")

    reportFile.write(processedACLEntries())




# MAIN

if __name__ is not '__main__':
    sys.exit()

auth_token = setSysAccess()
accessPolicy = []
aclEntries = []
accessPolicy = getAccessPolicy(auth_token, "/policy/accesspolicies", '', '', 'MMI')

for element in accessPolicy:
    aclEntry = getAccessPolicy(auth_token, "/policy/accesspolicies/", element[2], '/accessrules', element[3])
    if aclEntry:
        for element in aclEntry:
            aclEntries.append(element)
aclDetails = []
for element in aclEntries:
    # getACLDetails(auth_token, api_function, container_uuid, api_subfunction, object_uuid, tag):
    item = getACLDetails(auth_token, "/policy/accesspolicies/", element[1], '/accessrules/', element[2], element[0])
    if item:
        aclDetails.append(item)

x = open('file.text', '+w')
x.write(str(aclDetails))
writeFile()


print('done')
