# Firepower Management Console Access Policy Review Generator
v201909.1rc - Sep 16, 2019

I already said this is my first code so no trolling please :)

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


v201909.0a - Sep 10, 2019

Note: This is literally my first python code beside the "Hello World" and print (x + 2)!



Fixed bugs
* dealing with offset, now 1000 instead of 25
* dealing with policy inheritance, Cisco TAC promised they will figure a bug for the issue involving missing Object UUID in child Access Policy inherited from Parent Policy

The script will spit out a text document that contains a TAB separated fields, copy and paste it in excel and wallah, you got yourself a half-ass Firewall Policy Review document!


Please feel free to report bugs, suggest modification, or share your experience!


Sam Jbori
-------------------------------------------------------------------------------------------------------------------------------
