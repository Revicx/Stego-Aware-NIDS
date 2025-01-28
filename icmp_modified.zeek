# Load necessary scripts
@load policy/tuning/json-logs.zeek
@load iat.zeek

# Define custom record type for ID
type ID: record {
	src: addr;
	dst: addr;
};

# Global variables
global IAT_tab: table[addr] of IAT = {};
global ICMP_ID: table[ID] of count = {};
global id_seq: table[count] of count = {};
global t: time;
global id1: ID;
global counter: int;

# Redefine actions for Weird framework
redef Weird::actions: table[string] of Weird::Action += {
	["Possible_Steganography"] = Weird::ACTION_NOTICE,
};

# Add custom notice type
redef enum Notice::Type += { Possible_Steganography1 };

# Initialization event
event zeek_init() {
	t = current_time();
	counter = 0;
}

# ICMP echo request event
event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) {
	counter = counter + 1;

	# Calculate IAT intervals
	cheek_intervals(IAT_tab, c$id$orig_h, c, t);
	id1 = ID($src = c$id$orig_h, $dst = c$id$resp_h);

	# Check for ICMP ID steganography
	if (id1 in ICMP_ID) {
		if (ICMP_ID[id1] != id) {
			if (ICMP_ID[id1] + 1 < id) {
				print "possible stego!";
				NOTICE([$note=Possible_Steganography1,
						$msg="Possible ICMP ID Steganography",
						$sub="ID number is changing of ICMP is not appearing in order",
						$conn=c]);
				Weird::weird([
					$ts=network_time(),
					$name="Possible_Staeganography ID",
					$conn=c
					#$notice=T
				]);
				ICMP_ID[id1] = id;
			} else {
				ICMP_ID[id1] = id;
			}
		}
	} else {
		ICMP_ID[id1] = id;
	}

	# Check for sequence steganography
	if (id in id_seq) {
		if (seq == 0 || id_seq[id] + 1 == seq || id_seq[id] == seq) {
			id_seq[id] = seq;
		} else {
			print "Possible seq stego";
			NOTICE([$note=Possible_Steganography,
					$conn=c,
					$id=c$id,
					$msg="Possible ICMP SEQ Steganography",
					$sub="Sequence number of ICMP is not appearing in order",
					$ts=network_time()]);
			Weird::weird([
				$ts=network_time(),
				$name="Possible_Staeganography SEQ",
				$conn=c,
				$notice=T
			]);
			id_seq[id] = seq;
		}
	} else {
		id_seq[id] = seq;
	}
}
