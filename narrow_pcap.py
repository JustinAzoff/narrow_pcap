#!/usr/bin/env python
import os
import subprocess
import sys

def gen_exp(pkt_lst, s=None, e=None):
    parts = []
    if pkt_lst:
        parts.append(' || '.join("frame.number==%d" % x for x in pkt_lst))
    if s:
        parts.append("frame.number >= %s" % s)
    if e:
        parts.append("frame.number <= %s" % e)

    return " && ".join("(%s)" % x for x in parts)

def remove(lst, x):
    return [i for i in lst if i != x]

def pkt_count(pcap):
    out = subprocess.check_output(["tcpdump", "-nr", pcap])
    return len(out.splitlines())

class Narrow:
    def __init__(self, pcap, test_script):
        self.pcap = pcap
        self.test_script = test_script

    def is_bad(self, pkt_lst=None, start=None, end=None):
        #print pkt_lst, start, end
        exp = gen_exp(pkt_lst, start, end)
        subprocess.check_call(["tshark", "-r", self.pcap, "-Y", exp, "-w", "_test.pcap"])
        try:
            subprocess.check_call([self.test_script, "_test.pcap"])
            return False
        except subprocess.CalledProcessError:
            return True

    def run(self):
        s = last_bad_s = 0
        e = last_bad_e = pkt_count(self.pcap)
        print "Finding problem in %d packets" % e 

        #determine start and end
        while self.is_bad(start=s,end=e):
            last_bad_s = s
            s += 10
        s = last_bad_s
        print "apx. start packet", s
        while self.is_bad(start=e, end=e):
            last_bad_e = e
            e -= 10
        e = last_bad_e
        print "apx. end packet", e

        lst = range(s, e+1)

        #remove individual packets
        if not self.is_bad(lst):
            return
        print "OK Packets:"
        for x in lst:
            new_list = remove(lst, x)
            if self.is_bad(new_list):
                lst = new_list
                print x,
                sys.stdout.flush()
        print

        self.is_bad(lst)
        print "Final packet list", lst

if __name__ == "__main__":
    pcap = sys.argv[1]
    check_script = sys.argv[2]
    Narrow(pcap, check_script).run()
