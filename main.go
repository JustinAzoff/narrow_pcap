package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type pkt struct {
	data []byte
	ci   gopacket.CaptureInfo
}

type packetSelection struct {
	list  []int
	start int
	end   int
}

func (ps packetSelection) String() string {
	return fmt.Sprintf("%d:%d minus %d packets", ps.start, ps.end, len(ps.list))
}

func ReadAllPackets(filename string) ([]pkt, error) {
	var packets []pkt
	f, _ := os.Open(filename)
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return packets, err
	}
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			return packets, err
		}
		packets = append(packets, pkt{data, ci})
	}
	return packets, err
}

func writeFiltered(filename string, packets []pkt, sel packetSelection) (int, error) {
	var written int
	sel_map := make(map[int]bool)
	for _, pkt := range sel.list {
		sel_map[pkt] = true
	}

	f, err := os.Create(filename)
	if err != nil {
		return 0, err
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
	for idx, p := range packets {
		if !(idx >= sel.start && idx <= sel.end) {
			continue
		}
		if len(sel.list) > 0 && sel_map[idx] {
			continue
		}
		w.WritePacket(p.ci, p.data)
		written++
	}
	f.Close()
	return written, nil
}

func isBad(pcap, script string) (bool, string, error) {
	cmd := exec.Command(script, pcap)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		return true, "", err
	}
	out, err := ioutil.ReadAll(stdout)
	if err != nil {
		return true, "", err
	}
	err = cmd.Wait()
	return err != nil, string(out), nil
}

func check(packets []pkt, script string, sel packetSelection) (bool, int, string, error) {
	written, err := writeFiltered("_check.pcap", packets, sel)
	if err != nil {
		return false, 0, "", err
	}
	bad, out, err := isBad("_check.pcap", script)
	return bad, written, out, err
}

func reduce(v int) int {
	if v == 1 {
		return 1
	}
	return v / 4
}

func permRange(a, b int) []int {
	nums := rand.Perm(b - a)
	for idx := range nums {
		nums[idx] += a
	}
	return nums
}

func findEdge(packets []pkt, script string, selection packetSelection, which string) (packetSelection, error) {
	increment := 16384 //FIXME
	var last_bad_selection packetSelection
	for {
		bad, written, out, err := check(packets, script, selection)
		log.Printf("Selection=%s tested=%d bad=%v out=%s", selection, written, bad, out)
		if err != nil {
			return selection, err
		}
		if bad {
			last_bad_selection = selection
		}
		if !bad { // this worked? go back
			log.Printf("setting selection back to %s", last_bad_selection)
			selection = last_bad_selection
			increment = reduce(increment)
			if increment <= 1024 {
				break
			}
		}
		for increment != 1 && selection.start+increment > selection.end {
			increment = reduce(increment)
		}
		if which == "lower" {
			selection.start += increment
		} else {
			selection.end -= increment
		}
	}
	selection = last_bad_selection

	return selection, nil
}

func randomRemove(packets []pkt, script string, selection packetSelection) (packetSelection, error) {

	packetIndexes := permRange(selection.start, selection.end+1)

	var last_bad_selection packetSelection
	last_bad_selection = selection
	for idx, packetIndex := range packetIndexes {
		selection.list = append(selection.list, packetIndex)
		bad, written, out, err := check(packets, script, selection)
		log.Printf("%4d/%4d Selection=%s tested=%d bad=%v %s", idx, len(packetIndexes), selection, written, bad, out)
		if err != nil {
			return selection, err
		}
		if bad {
			last_bad_selection = selection
		} else {
			selection = last_bad_selection
		}
	}
	selection = last_bad_selection
	return selection, nil
}

func narrow(pcap, script string) error {
	start := time.Now()
	log.Printf("Narrowing pcap %s using script %s", pcap, script)
	log.Printf("Reading all packets...")
	packets, err := ReadAllPackets(pcap)
	if err != nil {
		return err
	}
	log.Printf("Read %d packets in %d seconds", len(packets), time.Since(start)/time.Second)
	var selection packetSelection
	selection.start = 0
	selection.end = len(packets)
	selection, err = findEdge(packets, script, selection, "lower")
	if err != nil {
		return err
	}
	selection, err = findEdge(packets, script, selection, "upper")
	if err != nil {
		return err
	}
	log.Printf("Final selection after trimming ends: %v", selection)
	selection, err = randomRemove(packets, script, selection)
	if err != nil {
		return err
	}
	log.Printf("Final selection: %v", selection)
	bad, written, out, err := check(packets, script, selection)
	log.Printf("Selection=%s packets=%d bad=%v out=%s", selection, written, bad, out)
	return err
}

func main() {
	flag.Parse()
	args := flag.Args()
	err := narrow(args[0], args[1])
	if err != nil {
		log.Fatal(err)
	}
}
