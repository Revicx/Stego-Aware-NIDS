@load vtcs.zeek
@load policy/tuning/json-logs.zeek

# global id : ID;
global id_changes_counter = 0;
global TCP_Urgent = F;
global old_seq_TCP = 0;

global TCP_seq : table[ID] of VTC = {};
global TCP_port: table[ID] of VTC = {};
global TCP_win: table[ID] of VTC = {};

# global counter : int;


# event zeek_init() {
# 	counter = 0;
# }


event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
	# counter = counter + 1;
	# print "===============";
	# print counter;
	for (i in flags)
		{
	#check URG flag If it exist set it to TRUE
			if (i == "U")
				{
				# print "Urgent pointer is on";
				TCP_Urgent = T;
				}
	#check for RST flag and payload
			if (i == "R" && payload != "")
				{
				print "Possible Stego, the RST flag is up and the payload is not empty.";
				NOTICE([$note=Possible_Steganography,
				 	$msg = "Possible RST/payload TCP steganography",
				 	$ts=network_time(),
				 	$sub = "The RST flag is set and payload is not empty.",
				 	$conn = c]);
				}
		}
	old_seq_TCP = seq;
	}


event new_packet (c: connection, p: pkt_hdr){
	#Reserved bits check
	if(p ?$ tcp && p$tcp$reserved != 0 ){
			# print "Reserved bits number is : ",p$tcp$reserved;
			# print "Possible Reserved Bits Stego";
			 NOTICE([$note=Possible_Steganography,
                                   $msg = "Possible reserved bits TCP steganography",
			 	  $ts=network_time(),
                                   $sub = "TCP reserved bits are not equal to zero",
                                   $conn = c]);
                        Weird::weird([
                        $ts=network_time(),
                        $name="Possible_Staeganography",
                        $conn=c,
                        $notice=T]); #check whats going on over here
	}
	#check Urgent pointer
	if(p ?$ tcp){
		if(p$tcp$reserved != 0 && !TCP_Urgent){
			#print "Possibile stego URG flag is 0 and urgent pointer exists";
			NOTICE([$note=Possible_Steganography,
                		                $msg = "Possible urgent pointer TCP steganography",
        	                	        $sub = "Possibile stego URG flag is 0 and urgent pointer exists",
						   				$ts=network_time(),
	                                	$conn = c]);
		}
	}

	
	if(p ?$ ip && p ?$ tcp){
		id = ID($src = p$ip$src, $dst = p$ip$dst);
		if(id in TCP_seq && id$src != local_address)
		{
			TCP_seq[id]$a += 1;
			print(TCP_seq[id]$a);
			if(p$tcp$seq > TCP_seq[id]$v)
				{
					TCP_seq[id]$c += 1;
					if(TCP_seq[id]$c >= 20){
						print "clear data";
						TCP_seq[id]$c = 1;
						TCP_seq[id]$a = 100;
					}
				}
			else
				{
					#TCP_seq[id]$c -= 1;
					#print "DOWN!";
					if( |TCP_seq[id]$a / TCP_seq[id]$c| < 20){
						print(TCP_seq[id]$a);
						print(TCP_seq[id]$c);
						print("possible stego seq");
						NOTICE([$note=Possible_Steganography,
                		                   $msg = "Possible seq number TCP steganography",
        	                	           $sub = "SEQ number not increasing",
						   $ts=network_time(),
	                                	   $conn = c]);
						TCP_seq[id]$c = 1;
						TCP_seq[id]$a = 100;
					}
				}
			TCP_seq[id]$v = p$tcp$seq;
		}
		else if(p$ip$src != local_address)
		{
			TCP_seq[id] = VTC($v = p$tcp$seq, $t = network_time(), $c = 1, $a=100);
		}
	# }

		if(id in TCP_port){
		#	print "same address";
				if(p ?$ tcp && TCP_port[id]$v != port_to_count(p$tcp$sport))
				{
					print "new source port for same address";
						if(network_time() - TCP_port[id]$t < 1min){
							TCP_port[id]$c += 1;
							if( |TCP_port[id]$a / TCP_port[id]$c| < 20){
									print "possible port stego";
		      					NOTICE([$note=Possible_Steganography,
                                                   		$msg = "Possible source port TCP steganography",
                                                  		$sub = "Source port number changing too frequently",
								$ts=network_time(),
                                                   		$conn = c]);
															TCP_port[id]$t = network_time();
							TCP_port[id]$c = 1;
							TCP_port[id]$a = 100;
							}
						}
						else{
							TCP_port[id]$t = network_time();
							TCP_port[id]$c = 1;
							TCP_port[id]$a = 100;
						}
					TCP_port[id]$v = port_to_count(p$tcp$sport);
				}
		}	
		else {
		#	print "new address";
			TCP_port[id] = VTC($v = port_to_count(p$tcp$sport), $t = network_time(), $c = 1, $a = 100 );
		}


		if(id in TCP_win && p$ip$src != local_address){
		#	print "same address";
				if(p ?$ tcp && TCP_win[id]$v != p$tcp$win)
				{
					print "new window port for same address";
						if(network_time() - TCP_win[id]$t < 1min){
							TCP_win[id]$c += 1;
							if( |TCP_win[id]$a / TCP_win[id]$c| < 10){
									print "possible window stego";
									print p$ip$src;
		      					NOTICE([$note=Possible_Steganography,
                                                   		$msg = "Possible window TCP steganography",
                                                  		$sub = "Window changing too frequently",
								$ts=network_time(),
                                                   		$conn = c]);
							TCP_win[id]$t = network_time();
							TCP_win[id]$c = 1;
							TCP_win[id]$a = 100;
							}
						}
						else{
							TCP_win[id]$t = network_time();
							TCP_win[id]$c = 1;
							TCP_win[id]$a = 100;
						}
					TCP_win[id]$v = p$tcp$win;
				}
		}	
		else if(p$ip$src != local_address){
		#	print "new address";
			TCP_win[id] = VTC($v = p$tcp$win, $t = network_time(), $c = 1, $a = 100 );
		}
	}
	#Unset urgent pointer
	TCP_Urgent = F;
}
