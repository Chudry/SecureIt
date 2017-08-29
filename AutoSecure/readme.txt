Security Automation suite to ensure Infrastructure and applications are well secured against intrusion, hacker attacks.

Objective:
* To ensure data privacy. 
* Prevent data leakage. 
* Ensure best infrastructure deployment practices.
* Scan vulnerabilities of Infrastructure and Web Applications.
* Break the protection shield through exploits ( Not to run any payload which might hamper the system )
* Report vulnerabilities per host.
* Provide remediation measures.
* Holistic security report.


Tools Used:
* Nmap : Port Scanner.
* Nessus : Vulnerability Assessment. 
* Metasploit Framework : Security framework which integrates lot of testing tools ( also Nmap & Nessus ). Helps in exploiting the system with huge database of exploits. 


Automation Suite:
* Language : Python
* WorkFlow:
	* Use Nmap from Metasploit framework to scan all the hosts
	* List hosts which are up which contains Open ports.
	* On each host, do vulnerability scan using Nessus.
	* Parse the Nessus report against severity per host
	* Publish the holistic report.
* Output contains list of all the hosts which are Up, running and have some open ports. Vulenrabilities will be reported agains each host.
* High level report on Infrastructure, Applications, Databases.

