
import json
from collections import Counter

def getSuccessLoginCommands(data):
    list = []
    commandList = []
    for i in data:
        if i['eventid'] == 'cowrie.login.success' or i['eventid'] == 'cowrie.command.input' :
            list.append(i)
    for i in list:
        if i['eventid'] == 'cowrie.login.success':
            count = 5
            continue
        if count > 0 and count <= 5:
            if i['eventid'] == 'cowrie.command.input':
                commandList.append(i['message'])
                count = count - 1
                
    return Counter(commandList).most_common(5)

def findMaxFailedlogins(data):
    max = 0
    count = 0
    for i in data:
        if i['eventid'] == 'cowrie.login.failed':
            count = count + 1
            if count >= max:
                max = count
        if i['eventid'] == 'cowrie.login.success':
            count = 0
    return max

def countJsonKey(data, key):
    list = []
    for i in data:
        list.append(i[key])
    return Counter(list)

def getParsedList(data, key, value):
    failedLogins = []
    for i in data:
        if i[key] == value:
            failedLogins.append(i)
    return failedLogins

logList = []
print("Started Reading JSON file which contains multiple JSON document")
with open('honey.log') as f:
    for jsonObj in f:
        logDict = json.loads(jsonObj)
        logList.append(logDict)
        
failedLogins = getParsedList(logList, 'eventid', 'cowrie.login.failed')
print("The number of failed login attempts is: ")
print(len(failedLogins))

rankedFailedUsername = countJsonKey(failedLogins, 'username').most_common(10)
print("The most common username for failed logins and the number of times it was used was: ")
print(rankedFailedUsername[0])

successfulLogins = getParsedList(logList, 'eventid', 'cowrie.login.success')
print("The number of successful logins is: ")
print(len(successfulLogins))

rankedSuccessUsername = countJsonKey(successfulLogins, 'username').most_common(10)
print("The most common username for successful logins and the number of times it was used was: ")
print(rankedSuccessUsername[0])

rankedFailedIP = countJsonKey(failedLogins, 'src_ip').most_common(10)
print("The most common IP address for failed logins and the number of times it was used was: ")
print(rankedFailedIP[0])

rankedSuccessIP = countJsonKey(successfulLogins, 'src_ip').most_common(10)
print("The most common IP address for successful logins and the number of times it was used was: ")
print(rankedSuccessIP[0])

totalLoginsList = failedLogins + successfulLogins
rankedUsernamesLogin = countJsonKey(totalLoginsList, 'username').most_common(10)
print("The top 10 most common usernames for all logins and the number of times it was used was: ")
print(rankedUsernamesLogin)

successfulRootLogin = getParsedList(successfulLogins, 'username', 'root')
rankedRootLogin = countJsonKey(successfulLogins, 'src_ip').values()
print("The number of unique source IP addresses that had a successful root login on the first try is: ")
print(sum(value == 1 for value in rankedRootLogin))

totalRootLoginsList = getParsedList(totalLoginsList, 'username', 'root')
maxFailedRootAttempts = findMaxFailedlogins(totalRootLoginsList)
print("The maximum number of failed root logins before the first successful root log in is: ")
print(maxFailedRootAttempts)

commonCommandsAfterLogin = getSuccessLoginCommands(logList)
print("the five most common commands that are executed after a login are: ")
print(commonCommandsAfterLogin)

totalFailedRootLoginsList = getParsedList(totalRootLoginsList, 'eventid', 'cowrie.login.failed')
maxFailedRootAttemptsIP = countJsonKey(totalFailedRootLoginsList, 'src_ip').most_common(10)
print("The maximum number of failed root logins common IPS: ")
print(maxFailedRootAttemptsIP)