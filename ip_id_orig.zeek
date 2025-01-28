@load vtcs.zeek

global t_IP : table[ID] of VTC = {};

# This event handler is triggered for each new packet received.
# It checks if the packet contains an IP header and performs IP ID steganography detection.
# If the IP ID of the packet decreases unexpectedly multiple times within a short time period,
# it raises a notice indicating possible IP ID steganography.
#
# Parameters:
# - c: The connection object representing the network connection.
# - p: The packet header object containing information about the packet.
#
# Note: This code assumes the existence of a global table 't_IP' to store IP ID information.
# The table 't_IP' is a dictionary where the keys are IP addresses and the values are VTC objects.
# The VTC object contains the IP ID value, the last observed time, the count, and the average.
#
event new_packet(c: connection, p: pkt_hdr) {
        if (p ?$ ip) {
                # Check if the packet contains an IP header

                id = ID($src = p$ip$src, $dst = p$ip$dst);

                if (id in t_IP) {
                        # IP ID already observed for this IP address

                        t_IP[id]$a += 1;

                        if (p$ip$id < t_IP[id]$v) {
                                # IP ID decreased unexpectedly

                                t_IP[id]$v = p$ip$id;

                                if (network_time() - t_IP[id]$t < 1min) {
                                        # IP ID decreased multiple times within a minute

                                        t_IP[id]$c += 1;

                                        if (|t_IP[id]$a / t_IP[id]$c| < 20) {
                                                # Average IP ID change rate is less than 20

                                                print t_IP[id]$c, t_IP[id]$a;
                                                print "possible IP Id stego", p$ip$src;

                                                # Raise a notice indicating possible IP ID steganography
                                                NOTICE([$note=Possible_Steganography,
                                                                $ts=network_time(),
                                                                $msg="Possible IP ID Steganography",
                                                                $sub="ID number of IP decreased unexpected number of times",
                                                                $conn=c]);

                                                t_IP[id]$c = 1;
                                                t_IP[id]$t = network_time();
                                                t_IP[id]$a = 100;
                                                print "Reset Data";
                                        }
                                } else {
                                        # IP ID decreased after a long time

                                        t_IP[id]$c = 1;
                                        t_IP[id]$t = network_time();
                                        t_IP[id]$a = 100;
                                        print "Reset Data";
                                }
                        } else {
                                # IP ID increased or remained the same

                                t_IP[id]$v = p$ip$id;
                        }
                } else if (p$ip$src != local_address) {
                        # New IP address observed, store its IP ID

                        t_IP[id] = VTC($v=p$ip$id, $t=network_time(), $c=1, $a=100);
                }
        }
}



