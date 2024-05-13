#inter arival time
@load policy/tuning/json-logs.zeek
redef enum Notice::Type += { Possible_Steganography };

type IAT: record {
     c: count;
     v: vector of interval;
     t: time;
};

function variance(vec: vector of interval, cou: count){
	local sum : double = 0;
	local avg : double = 0;
	local var : double = 0;
	local cv : double = 0;
	local vec2: vector of double;
    print vec;
	for (i in vec){
		sum += |vec[i]|;
	}
	avg = |sum/cou|;
	print "average: ",avg;
	for (i in vec){
		print |(|vec[i]|-avg)|;
		vec2[i] = |(|vec[i]|-avg)| * |(|vec[i]|-avg)|;
	}
	sum = 0;
	for (i in vec2){
		 print vec2[i];
		 sum += vec2[i];
	}
	print "vector: ",vec;
	print "sum: ",sum;
	print "count: ",cou;

	var = |sum/cou|;
	print "varinace: ",var;

	cv = sqrt(var)/avg;
	print "cv: ",cv;

	#sqare root of variance / mean = CV

	#here you can add additional parameter to check the variance

	if(cv > 0.8){
		print "possible stego";
		NOTICE([$note=Possible_Steganography,
            $msg = "Possible steganography",
			$ts = network_time(),
            $sub = "The CV is quite high"]);
    }
}

function cheek_intervals(tab: table[addr] of IAT, address: addr, c: connection, t: time){
	if(address in tab){
		if(network_time() - tab[address]$t < 5sec){
			tab[address]$v += network_time() - tab[address]$t;
		}
		#check current time
		tab[address]$t = network_time();
		
		#another packet cought
		#print tab[address]$c;
		#print tab[address]$v;
		tab[address]$c += 1;
		#after one minute check the interval 
		if(tab[address]$c > 10){
			# print tab[address]$v;
			local vo: vector of interval = sort(tab[address]$v);
			for (i in vo){
				# print "interval: ",|vo[i]|;
				if (i != |vo|-1 && |vo[i]| != 0){
					# print "delta: ",|vo[i]-vo[i+1]|;
					# print "devided ",|(|vo[i]-vo[i+1]|)/vo[i]|;
					if(|(|vo[i]-vo[i+1]|)/vo[i]| > 0.5){
						print "possible stego";
						NOTICE([$note=Possible_Steganography,
                            $msg = "Possible steganography",
							$conn = c,
							$ts = network_time(),
                            $sub = "The relaive difference beetwen adjancent intervals is significantly high"]);
                                                }
					}
				}
			variance(tab[address]$v, tab[address]$c);
			# print "new set";
			tab[address]$c = 0;
			tab[address]$v = vector();
			#set time to last recived time value.
			t = tab[address]$t;
			}
		}
	else{
		tab[address] = IAT($c = 0, $t = network_time(), $v = vector());
	}

}



