Narrow PCAP
===========

Have a pcap file that is breaking your analysis software?  Need to figure out
which packets specifically are causing a problem?

Write a check script/program/whatever.  A partial pcap will be passed as $1

    #!/bin/sh
    rm -f dns.log
    bro -r $1
    if [ ! -e dns.log ]; then
        exit 0
    fi

    if egrep -q "bad log entry here" dns.log ; then
        exit 1
    fi
    exit 0 


Run your test:

    $ time narrow_pcap.py bad_dns.pcap ./dns_check
    reading from file bad_dns.pcap, link-type EN10MB (Ethernet)
    Finding problem in 162 packets
    apx. start packet 50
    apx. end packet 162
    OK Packets:
    [70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89] [90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109] [130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149] [55, 56, 57, 58, 59] [60, 61, 62, 63, 64] [65, 66, 67, 68, 69] [115, 116, 117, 118, 119] [120, 121, 122, 123, 124] [125, 126, 127, 128, 129] [155, 156, 157, 158, 159] [160, 161, 162] [50] [51] [52] [53] [110] [113] [114] [151] [152] [153] [154]
    Final packet list [54, 111, 112, 150]

    real    0m19.824s
    user    0m14.872s
    sys     0m3.137s

And now you have _test.pcap which contains just the problem packets:

    $ du -h bad_dns.pcap _test.pcap
     40K    bad_dns.pcap
    4.0K    _test.pcap
