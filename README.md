# Nettrail

Nettrail is a python tool that aims to assist in performing and interpreting the results of [Nmap](https://nmap.org/) scans in large networks. The tool is work-in-progress and primarily used by me in my own assignments, so use it with a grain of salt.

In some assignments it is necessary to scan alot of hosts (1000+) which makes a manual inspection of the results tiresome/impossible. Netrail allows to specify a list of targets that are to be scanned, performs the nmap scans and stores the results. It facilitates interpretation of the results by aggregation and search features. For instance, it is possible to search the scan results for all hosts that have port 80 open via `nettrail search -p 80` or get a deduped list of all services that run on all hosts via `nettrail analyze -m flatlist`.

## Setup

[Nmap](https://nmap.org/) has to be installed and has to be in the PATH.

## How to use

To enable SYN scans, nettrail has to be executed with root privileges.

Nettrail has multiple modes in which it can be used.

~~~
usage: nettrail [-h] [-o OUTPUT_PATH] [-v] {discover,scan,show,search,analyze,cleanup} ...

nettrail, a tool to make nmap-based network recon digestable.

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_PATH        Path where scan results are stored. (Default: ./output)
  -v                    Enable verbose logging

Subcommands:
  {discover,scan,show,search,analyze,cleanup}
    discover            Run in discover mode to find live hosts in the subnet
    scan                Run in scan mode
    show                Show results for provided target
    search              Searches for hosts that have results which match search criteria
    analyze             Analyze all performed scans.
    cleanup             Do nothing. Just update the folder names
~~~

### Discover

The `discover` mode can be used to perform host discovery. Most assignments begin with enumerating machines that are connected to the network. The output of the command can be used to generate host lists that can be fed to the `scan` mode in the next step.

### Scan

The `scan` mode can be used to perform scans of multiple targets and store the results in the output folder. Targets can be supplied on the commandline or in a file that is supplied via the `-i` parameter. Supplying targets via file allows *nettrail* to interface well with itself and *bloodtrail* which allows to generate lists of interesting targets based on Bloodhound data.

The scan results are put in the output folder that is set via `-o`. One folder is created for every scanned target and the nmap results are put in it. The folder name is the hostname and a comment that can be supplied in the target list that is supplied via `-i`. The comment has to be seperated from the hostname by a blank space. Example - Target file: `C3000.domain.local Computer of Jens` -> Foldername: `C3000.DOMAIN.LOCAL___Computer of Jens`

### Show

The `show` mode can be used to show scan results for a specific target. The output is identical to a regular Nmap scan.

### Search

The `search` mode can be used to search the scan results for hosts that match the supplied search string and/or that have the supplied ports open. Example: `nettrail search -p80 Apache`. This can be particularly useful when a vulnerable service has been identified using `analyze` and it has to be determined where it is running.

### Analyze

The `analzye` mode can be used to view aggregated scan results of all hosts or of the hosts that are supplied via the `-H` parameter. Currently, two modes are supported: 

* `flatlist` aggregates all services that are running on the scanned hosts and eliminates duplicates. This saves time when scanning for vulnerable software versions, since every service only occurs once even if it runs on many machines.
* `classes` lets nettrail categorize all hosts in equivalence classes based on the open ports. For instance, in typical assignments the majority of client workstations is setup (close to) identically. It can save time it suffices to investigate just one representant of the equivalence class. Beware though, that this is an approximation. Just because the same ports are open does not mean that the same services are running.

### Cleanup

The `cleanup` mode can be used to update the comments in the foldernames according to the comments that are supplied in the `-i` file.