# Version 201909.NEXT
# Release Candidate

import json
import os
import sys
import time
import datetime
import requests
import tkinter as tk

# Disable SSL verifications warning
import urllib3

urllib3.disable_warnings()


# Begin Staging The Script by Collecting Access Information and generating proper tokens
def getAuthToken(fmcIP, fmcUser, fmcPass):
    global domain_uuid
    url = 'https://' + fmcIP + '/api/fmc_platform/v1/auth/generatetoken'
    headers = {'Content-Type': 'application/json'}
    try:
        reqResp = requests.post(url, headers=headers, auth=requests.auth.HTTPBasicAuth(fmcUser, fmcPass), verify=False)

    except Exception as e:
        print('Function getAuthToken failed...', e)
        sys.exit('Authentication Failure: Failed to retrieve token... Error Result: GameStopper')
    else:
        if reqResp.status_code == 401:
            sys.exit('FMC responded with Unauthorized Access HTTP 401... Function: getAuthToken... Result: GameStopper...')
        domain_uuid = reqResp.headers.get('DOMAIN_UUID', default=None)
        return reqResp.headers.get('X-auth-access-token', default=None)

    sys.exit('How Did I get here???... Function: getAuthToken... Error Result: GameStopper')


def inputWindow():
    configData = {}
    master = tk.Tk()
    master.title('FMC ACP Review by Sam Jbori')
    tk.Label(master, text='FMC IP   :').grid(row=0)
    tk.Label(master, text='User Name:').grid(row=1)
    tk.Label(master, text='Password :').grid(row=2)
    tk.Label(master, text='Org Name :').grid(row=3)
    fmcIP = tk.Entry(master)
    fmcIP.grid(row=0, column=1)
    uName = tk.Entry(master)
    uName.grid(row=1, column=1)
    pWord = tk.Entry(master)
    pWord.grid(row=2, column=1)
    #pWord.config(show='W')
    orgID = tk.Entry(master)
    orgID.grid(row=3, column=1)

    tk.Button(master, text='Okay', command=master.quit).grid(row=10, column=10, sticky=tk.W, pady=4)
    master.mainloop()

    configData.update(FMC_IP= fmcIP.get())
    configData.update(FMC_USER= uName.get())
    configData.update(FMC_PASS= pWord.get())
    configData.update(ORG_ID= orgID.get())

    return configData  # dict


def setScriptVariables():
    global configFile
    rebuildConfigData = False
    print('Checking for config file...')
    if os.path.isfile(configFile):
        print('Config file found, processing saved information...')
        with open(configFile, 'r') as config_file:
            configData = json.loads(config_file.read())
        if 'FMC_IP' in configData and 'FMC_USER' in configData and 'FMC_PASS' in configData and 'ORG_ID' in configData:
            print('Config file loaded... DOESN\'T GRANTEES CORRECT DATA, DELETE config.json TO START FRESH...')
        else:
            print('Corrupted config file...\nRebuilding Config File, press CTRL + C to cancel...')
            time.sleep(5)
            print('Rebuilding')
            rebuildConfigData = True

    else:
        print('No config file found, using user input...')
        rebuildConfigData = True

    if rebuildConfigData:
        # configData = {
        #     'FMC_IP': '',
        #     'FMC_USER': '',
        #     'FMC_PASS': '',
        #     'ORG_ID':'',
        # }
        configData = inputWindow()
        with open(configFile, '+w') as output_file:
            json.dump(configData, output_file, indent=4)

    configData.update(FMC_AUTHTOKEN=getAuthToken(configData['FMC_IP'], configData['FMC_USER'], configData['FMC_PASS']))
    del configData['FMC_USER'] # remove user name
    del configData['FMC_PASS'] # and password from the program

    return configData
# End Staging The Script by Collecting Access Information and generating proper tokens
# The result should be 2 variables, accessVar and domain_UUID

#Begin Policy and Entry Data Collection Section

def getAccessPolicy(fmcIP, auth_token, domain_uuid, api_function, container_uuid, api_subfunction, tagName, tagID, plcName, plcID):

    entryBuilder = []
    global timeStamp
    api_path = "/api/fmc_config/v1/domain/" + domain_uuid + api_function + container_uuid + api_subfunction  # param
    url = 'https://' + fmcIP + api_path + '?offset=0&limit=1000'
    headers = {'Content-Type': 'application/json', 'X-auth-access-token': auth_token}

    try:
        apiResp = requests.get(url, headers=headers, verify=False, )

    except Exception as e:
        print(e)
        sys.exit('Error unknown to the function logic... Function: getAccessPolicy... Result: GameStopper...\n')

    if apiResp.status_code is 200:
        print('API Call pulled successfully...')
    elif apiResp.status_code is 404:
        print('Object Not Found... No worry it\'s most likely bug id CSCvq67271... Result: Ignore...')
        return None
    elif apiResp.status_code is 429:
        print('FMC Sent HTTP 429, pausing for', int(65 - ((time.time() - timeStamp)%60)), '... Function: getAccessPolicy... Result: Delay, sit tight...')
        time.sleep(65 - ((time.time() - timeStamp)%60))
        print('Proceeding with changes...')
        timeStamp = time.time()
        apiResp = getAccessPolicy(fmcIP, domain_uuid, auth_token, api_function, container_uuid, api_subfunction, tagName, tagID, plcName, plcID)
    elif apiResp.status_code is 401:
        sys.exit('FMC responded with Unauthorized Access HTTP 401... Function: getAccessPolicy... Result: GameStopper...')

    else:
        print('Getting HTTP', apiResp.status_code)
        sys.exit('Error unknown to the function logic... Function: getAccessPolicy... Result: GameStopper...\n')

    json_resp = json.loads(apiResp.text)
    if 'items' in json_resp:
        for element in json_resp['items']:
            if not plcID:
                print('Policy found, adding', element['id'], element['type'], element['name'])
            else:
                print('ACE found, adding', element['id'], element['type'], plcName+ '/' + element['name'])
            policyPair = {'TAG_NAME' : tagName, 'TAG_ID' : tagID, 'PLC_NAME' : plcName, 'PLC_ID' : plcID, 'DOMAIN_UUID' : domain_uuid, 'OBJECT_TYPE': element['type'], 'OBJECT_ID' : element['id'], 'OBJECT_NAME' : element['name']}
            entryBuilder.append(policyPair)
    if len(entryBuilder) is 0:
        print('Dummy policy', plcName,'- no entries - Skipping')
    else:
        print('Data Extracted...')


    return entryBuilder


def getACLDetails(fmcIP, auth_token, domain_uuid, api_function, container_uuid, api_subfunction, object_uuid, tagName, plcName):

    global timeStamp

    global e500
    headers = {'Content-Type': 'application/json', 'X-auth-access-token': auth_token}
    api_path = "/api/fmc_config/v1/domain/" + domain_uuid + api_function + container_uuid + api_subfunction + object_uuid
    url = 'https://' + fmcIP + api_path

    try:
        apiResp = requests.get(url, headers=headers, verify=False, )
    except Exception as e:
        print(e)
        sys.exit('Error unknown to the function logic... Function: getACLDetails... Result: GameStopper...\n')

    if apiResp.status_code == 200:
        print('API Call pulled successfully...')
    elif apiResp.status_code == 404 or apiResp.status_code == 500:
        print('Object Not Found... No worry it\'s most likely bug id CSCvq67271... Result: Ignore...', apiResp.status_code)
        return None
    elif apiResp.status_code == 429:
        print('FMC Sent HTTP 429, pausing for', int(65 - ((time.time() - timeStamp)%60)), ' seconds... Function: getACLDetails... Result: Delay, sit tight...')
        time.sleep(65 - ((time.time() - timeStamp)%60))
        print('Proceeding with changes...')
        timeStamp = time.time()
        apiResp = getACLDetails(fmcIP, auth_token, domain_uuid, api_function, container_uuid, api_subfunction, object_uuid, tagName, plcName)
        return apiResp
    elif apiResp.status_code == 401:
        sys.exit('FMC responded with Unauthorized Access HTTP 401... Function: getACLDetails... Result: GameStopper...')
    # elif apiResp.status_code == 500:
    #     e500 += 1
    #     if e500 > 49:
    #         sys.exit('Error HTTP 500 occur 50 times, time to shut this babe down')
    #     else:
    #         print('Getting HTTP 500', 50 - e500, 'remaining to shut this process down...')
    #         time.sleep(10)
    #         getACLDetails(fmcIP, auth_token, domain_uuid, api_function, container_uuid, api_subfunction, object_uuid,
    #                       tagName, plcName)
    else:
        print('Response code HTTP', apiResp.status_code)
        sys.exit('Error unknown to the function logic... Function: getACLDetails... Result: GameStopper...\n')

    json_resp = json.loads(apiResp.text)
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
        if 'urlCategoriesWithReputation' in urlElement:
            for catagories in urlElement['urlCategoriesWithReputation']:
                if 'catagory' in catagories:
                    for element in catagories:
                        pairingList = [element['type'], element['name']]
                        urlList.append(pairingList)

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

    print('Data Extraction completed successfully... Next')

    return {'DOMAIN_ID' :domain_uuid, 'TAG_ID' : tagName, 'PLC_ID': container_uuid, 'PLC_NAME': plcName,
            'OBJECT_ID': object_uuid, 'OBJECT_NAME' : json_resp['name'],'OBJECT_ENABLED' : json_resp['enabled'],
            'ZN_SRC' : srcZoneList, 'ZN_DST' : dstZoneList, 'SRC_NET' : srcNetList, 'DST_NET' : dstNetList,
            'PORT_SRC' : srcPrtList, 'PORT_DST' : dstPrtList, 'USERS' : userList, 'URLS' : urlList, 'APPS' : appsList}

def processedACLEntries(aceEntries):

    processedText = 'Orginization\tDomain ID\tPolicy Name\tPolicy ID\tRule\'s Name\tRule\'s ID\tEnabled\tSource Zone\t' \
                    'Destination Zone\tSource Network\tDestination Network\tSource Port\tDestination Port\tUsers\tURL\t' \
                    'Applications\n'
    for entry in aceEntries:
        processedText += str(entry['TAG_ID']) + '\t' + \
                         str(entry['DOMAIN_ID']) + '\t' + \
                         str(entry['PLC_NAME']) + '\t' +  \
                         str(entry['PLC_ID']) + '\t' + \
                         str(entry['OBJECT_NAME']) + '\t' + \
                         str(entry['OBJECT_ID']) + '\t' + \
                         str(entry['OBJECT_ENABLED']) + '\t' + \
                         str(entry['ZN_SRC']) + '\t' + \
                         str(entry['ZN_DST']) + '\t' + \
                         str(entry['SRC_NET']) + '\t' + \
                         str(entry['DST_NET']) + '\t' + \
                         str(entry['PORT_SRC']) + '\t' + \
                         str(entry['PORT_DST']) + '\t' + \
                         str(entry['USERS']) + '\t' + \
                         str(entry['URLS']) + '\t' + \
                         str(entry['APPS']) + '\n'

    return processedText


def writeReviewFile(aceEntries):
    fileName = 'FirewallReviews.txt' #+ str(datetime.datetime.today()) + '.txt'
    reportFile = open(fileName, "w")
    reportFile.write(processedACLEntries(aceEntries))



if __name__ is not '__main__':
    sys.exit()

timeStamp = time.time()  # Recover mechanism against HTTP 429 by the FMC

# System Access Global Variables!
domain_uuid = None          # FMC Global Domain UUID
configFile = 'config.json'  # Configfile name
accessPolicy = []           # Access Policy list of names, UUID,
aclEntries = []             # ACL Entries: Parent Policy, Parent UUID, Policy Name, UUID
aclDetails = []             # ACL Entries Detailed: Parent Policy, Parent UUID, Self Name, Self UUID,
                            # Zone SRC/DST, IP SRC/DST, Port SRC/DST, App, URL/Car, User/Group

accessVar = setScriptVariables() # Contain Sever IP 'FMC_IP' and AuthToken 'FMC_AUTHTOKEN'

print('Authentication Token retrieved: ********-****-****-****-****'+ str(accessVar['FMC_AUTHTOKEN'])[-8:])

print('Generating Access Policy list...')
accessPolicy = getAccessPolicy(accessVar['FMC_IP'], accessVar['FMC_AUTHTOKEN'], domain_uuid, "/policy/accesspolicies", '', '', accessVar['ORG_ID'], domain_uuid,'','')

for element in accessPolicy:
    print('Importing Policy', element['OBJECT_ID'], element["OBJECT_NAME"])
    aclEntry = getAccessPolicy(accessVar['FMC_IP'], accessVar['FMC_AUTHTOKEN'], domain_uuid, "/policy/accesspolicies/", element['OBJECT_ID'], '/accessrules', element['TAG_NAME'], element['TAG_ID'],element['OBJECT_NAME'], element['OBJECT_ID'])
    if aclEntry:
        for element in aclEntry:
            aclEntries.append(element)
del aclEntry
del element

for element in aclEntries:
    # getACLDetails(auth_token, api_function, container_uuid, api_subfunction, object_uuid, tagName, plcName):
    print('Retrieving ACE', element['OBJECT_ID'], element['PLC_NAME'] + '/' + element['OBJECT_NAME'])
    aclEntry = getACLDetails(accessVar['FMC_IP'], accessVar['FMC_AUTHTOKEN'], domain_uuid, "/policy/accesspolicies/",
                             element['PLC_ID'], '/accessrules/', element['OBJECT_ID'], element['TAG_NAME'], element['PLC_NAME'])
    if aclEntry:
        aclDetails.append(aclEntry)
writeReviewFile(aclDetails)

print('TADA...')
