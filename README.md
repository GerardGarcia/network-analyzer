network-analyzer
================
This tool dumps to a text file statistics about the IP packets that have been sent and received through the specified interface. It only captures IP datagrams over ethernet. 

It uses the libpcap library to capture the packets and the uthash library to create a hash table to store the statistics. Libpcacp has been chosen because it will ensure compatibility with most linux kernels and distributions and it will work with any generic network device. The tool has been analyzed with valgrind to ensure there are no memory leaks.

To achieve best results it is recommended to use a kernel version over 2.4 with PACKET_MMAP support. It is enabled by default in most newer Linux distributions. If this option is not enabled there will be an important performance penalty.

A profile analysis showed that almost 99% of CPU cycles consumed by this tool correspond to the kernel copying the network frames form the network device to the user-space memory region. To achieve less CPU usage  will be necessary to implement a specific solution that interacts directly with the network device memory (thus avoiding the cost of copying the frames to user level). The viability of this solution will depend on the model of the network card.

To use this tool it has to be launched as root or with the CAP_NET_RAW capabilities activated, the capabilities can be activated with the setcap utility:

sudo setcap cap_net_raw+ep ./net_analyze

The tool interface is:

./net_analyze [interface] [options]

And the supported options are:
       [-i | --ip]			Process only packets from or to this ip (it should be associated to the specified interface)
       [-s | --stats_path]	Path where to dump the statistics (default ./stats.log)
       [-d | --duration]	How many seconds between dumps (default dump is done at exit)
       [-p | --print]		Print to stdout
       [-h | --help]		Shows this help message

For example launching the tool as follows will behave like the command: tshark -E header=n -Q -a duration:60 -s 64 -n -z conv,ip,ip.addr==`hostname -i`, but in addition the stats will be dumped to ./stats.log.

./net_analyze eth0 -p -i `hostname -i` -d 60 -p

The output is:

[Time of last frame captured within this source and destination] 	[source] -> [destination]	[total number of bytes transfered]	[num of frames]
