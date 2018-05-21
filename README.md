# A Small Collection of Scripts

nmap_expand: take the results of a previously run nmap scan and sort results into various, more readable categories
	    
	input parameters:
		-s or --scripts to run more nmap scripts on found services (inoperable for the moment)
		-h or --help for more information
		
	on execution:
		script will request the path to a previously run nmap scan as path/to/file/name, relative paths are fine
		requires the presence of <name>.nmap and <name>.gnmap files, do not include the extensions in input path
		
	output: hosts separated by port and services, list of open ports, more to come
	
	$ ./nmap_expand.sh <name>
