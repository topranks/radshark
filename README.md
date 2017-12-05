# radshark

Python script to group RADIUS packets from a pcap file which relate to the same user session.

Uses the 'pyshark' interface to TShark to parse a pcap file and a multi-level dictionary structure to store the grouped objects.

parseFile() does the main work in this part.

outputCsv() is an ugly hack which just dumps all attributes from the packets belonging to a single session on one line of a csv.

I occasionally need this kind of thing in work.  May be useful to someone.
