@load vtcs.zeek

# Configuration variables
const DETECTION_WINDOW: interval = 90secs;  # Time window for detecting multiple decreases in IP ID
const INITIAL_AVERAGE = 50.0;  # Initial average value for new IP addresses
const MIN_THRESHOLD = 1.0;  # Minimum threshold for average IP ID change rate
const MAX_THRESHOLD = 150.0;  # Maximum threshold for average IP ID change rate
const ADJUSTMENT_FACTOR = 0.1;  # Factor for adjusting the threshold dynamically

global t_IP : table[ID] of VTC = {};

# Function to adjust the dynamic threshold based on recent observations
function adjust_threshold(id: ID): double {
    local rate = t_IP[id]$a / t_IP[id]$c;
    local threshold = INITIAL_AVERAGE;

    if (t_IP[id]?$threshold) {
        threshold = t_IP[id]$threshold;
    }

    if (rate < threshold) {
        threshold = threshold - (threshold - MIN_THRESHOLD) * ADJUSTMENT_FACTOR;
    } else {
        threshold = threshold + (MAX_THRESHOLD - threshold) * ADJUSTMENT_FACTOR;
    }

    return threshold;
}

event new_packet(c: connection, p: pkt_hdr) {
    if (p ?$ ip) {
        id = ID($src = p$ip$src, $dst = p$ip$dst);

        if (id in t_IP) {
            t_IP[id]$a += 1;  # Incrementing the absolute number of packets

            if (p$ip$id < t_IP[id]$v) {
                t_IP[id]$v = p$ip$id;

                if (network_time() - t_IP[id]$t < DETECTION_WINDOW) {
                    t_IP[id]$c += 1;  # Incrementing the count of decreases

                    t_IP[id]$threshold = adjust_threshold(id);

                    if (t_IP[id]$a / t_IP[id]$c < t_IP[id]$threshold) {
                        NOTICE([$note=Possible_Steganography,
                                $ts=network_time(),
                                $msg="Possible IP ID Steganography",
                                $sub="ID number of IP decreased unexpected number of times",
                                $conn=c]);

                        t_IP[id]$c = 1;
                        t_IP[id]$t = network_time();
                        t_IP[id]$a = 1;
                    }
                } else {
                    t_IP[id]$c = 1;
                    t_IP[id]$t = network_time();
                    t_IP[id]$a = 1;
                }
            } else {
                t_IP[id]$v = p$ip$id;
            }
        } else if (p$ip$src != local_address) {
            t_IP[id] = VTC($v=p$ip$id, $t=network_time(), $c=1, $a=1, $threshold=INITIAL_AVERAGE, $pkt=p);
        }
    }
}