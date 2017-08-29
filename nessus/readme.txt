Nessus Tool WorkFlow:

Templates:
* Default list of Templates are available.
* User can create a new template or use wel defined exisitng templates.

Policy:
* Create/ Update/ Delete your own policy. 

Scans:
* Create a custom defined policy
* Create a New scan using the custom defined policy
* Launch the new scan.





WorkFlow of Nessus Automation:
* Create a new Security policy using Nessus Web UI with following templates:
	-> Basic N/w Scan ( For now, Start with this )
	-> Audit Cloud Infrastructure.
	-> Bash ShellShock Detection.
	-> PCI Quarterly External Scan.
	-> Web Application Tests. 
* Create a new Scan for every defined Security Policy. 
* Launch the scan with list of hosts received from NMap( Running with open ports ).
* Obtain the scan-id of the latest launched scan.
* Downloand scan reports and render the results. 