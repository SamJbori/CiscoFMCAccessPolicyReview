# Firepower Management Console Access Policy Review Generator
----------------------------------------------------------------------------------------------------------------------------------------
# Release Name: BlackLip
v201909.1rc - Sep 16, 2019

I already said this is my first code so no trolling please :)

This script will use Cisco Firepower Management Console API to buid a human readable output file for all the Access Policy Controls (Access Rules) check (https://github.com/SamJbori/CiscoFMCAccessPolicyReview/blob/master/FirewallReviews2019-09-16%2001:18:42.649142.txt)

It will first generate an authentication token, FMC will disconnect any other active session for the user used to generate the token, this is the default behaiviour and you cant change it, the token will be used to authenticate and do the following

1. Generate a list of policies on the FMC
2. Generate a list of rules inside those policies
3. Generate a detailed list of all rules in those policies

the final outcome will include the following details
1. Orginization TAG: User Input
2. The system Global Domain UUID: usualy e276abec-e0f2-11e3-8169-6d9ed49b625f
3. Policy ID
4. Policy Name
5. Enabled?
6. Zone details
7. Network Details: source and destination
8. Port Details
9. URLs
10. Applications
11. User information

the output will be stored in the same folder the script will run, it will be a TAB delimit text and you can simply copy/paste into an xml file.

This will create a useful way to create a firewall review document to share with auditors (PCI, HIPPA, etc...)



Changes
* Improved pause timer to work around the 120 API request per minute limitation, now it will pause for the necessary time plus 5 seconds only
* Improved error recovery, now it recognize HTTP 404, 500, 401, and 429. if you received any other code before kindly report it so I can add it to the logic.
* Improved code structure, including using Dictionaries more and lists less, next release I am planning on gitting rid of lists completely
* Improved logging, now you can actually see what's going on and what is the script doing
* Improved Security, now user name and password are stored in a 'config.json' file not the code itself, and purged from the code the second the script get's the Auth Token, also less global variables and more arguments hand offs.
* Nice cute GUI for inputing username/password.
* Improved output file with more meaningful information...


If you like to see futures or other functionality, please feel free to ask!!!


# Sam Jbori 
# jbori.net
----------------------------------------------------------------------------------------------------------------------------------------

# Release Name: BrokenFoot
v201909.0a - Sep 10, 2019

Note: This is literally my first python code beside the "Hello World" and print (x + 2)!



Fixed bugs
* dealing with offset, now 1000 instead of 25
* dealing with policy inheritance, Cisco TAC promised they will figure a bug for the issue involving missing Object UUID in child Access Policy inherited from Parent Policy

The script will spit out a text document that contains a TAB separated fields, copy and paste it in excel and wallah, you got yourself a half-ass Firewall Policy Review document!


Please feel free to report bugs, suggest modification, or share your experience!


Sam Jbori
-------------------------------------------------------------------------------------------------------------------------------
