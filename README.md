# A Small Collection of Scripts

nmap_expand: take the results of a previously run nmap scan and sort results into various, more readable categories

	input: name of previous nmap scan, the presence of <name>.nmap and <name>.gnmap files
	
	output: hosts separated by port and services, list of open ports, more to come
	
	$ ./nmap_expand.sh <name>
