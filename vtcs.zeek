@load policy/tuning/json-logs.zeek
#redef enum Notice::Type += { Possible_Steganography };
redef Weird::actions: table[string] of Weird::Action += {
         ["Possible_Steganography"] = Weird::ACTION_NOTICE,
};

global local_address : addr = 192.168.0.235;

type VTC: record {
    v: int; #current value 
    t: time; #time of catching the packet
    c: count; #stego packets
    a: count; #absolute number of packets 
};


type STC: record {
    s: string; #current value 
    t: time; #time of catching the packet
    c: count; #stego packets
    a: count; #absolute number of packets 
};

type ITC: record {
     i: interval; #current value 
     t: time; #time of catching the packet
     c: count;
     a: count; #absolute number of packets 
};

type BTC: record {
     b: bool; #current value 
     t: time; #time of catching the packet
     c: count; #stego packets
     a: count; #absolute number of packets 
};

type IAT: record {
     c: count; #number of values in vector
     v: vector of interval; # investigated vactor value 
     t: time; #time of catching the packet
     a: count; #absolute number of packets 
};

function check_freqency(tab: table[addr] of STC, address: addr, value: string, name: string, period: interval &default=1min){
        tab[address]$a +=1;
        if(address in tab){
		print tab[address]$s;
		print value;
                if(tab[address]$s != value)
                                {
                                #print "new value for same address";
                                if(network_time() - tab[address]$t < period){
                                        tab[address]$c +=1 ;
                                        print tab[address]$c;
                                        if(|tab[address]$c / tab[address]$a| > 0.1){
                                                NOTICE([$note=Possible_Steganography,
							$ts=network_time(),
                                                        $msg = "Possible steganography",
                                                        $sub = name]);
                                                }
                                        }
                                else{
                                        tab[address]$c = 0;
                                        tab[address]$s = value;
                                        tab[address]$t = network_time();
                                        tab[address]$a = 0;
                                        }
                                }
        }
        else{
                tab[address] = STC($s = value, $t = network_time(), $c = 0, $a = 0);
        }
}

function check_freqency_t(tab: table[addr] of ITC, address: addr, value: interval, name: string){
         tab[address]$a +=1;
         if(address in tab){
                 if(tab[address]$i != value)
                                 {
                                 #print "new value for same address";
                                 if(network_time() - tab[address]$t < 1min){
                                         tab[address]$c +=1 ;
                                         print tab[address]$c;
                                         if( |tab[address]$c / tab[address]$a| > 0.1 ){
                                                 NOTICE([$note=Possible_Steganography,
							 $ts=network_time(),
                                                         $msg = "Possible steganography",
                                                         $sub = name]);
                                                 }
                                         }
                                 else{
                                         tab[address]$c = 0;
                                         tab[address]$i = value;
                                         tab[address]$t = network_time();
                                         tab[address]$a = 0;
                                         }
                                 }
         }
         else{
                 tab[address] = ITC($i = value, $t = network_time(), $c = 0, $a = 0);
         }
}

function check_freqency_b(tab: table[addr] of BTC, address: addr, value: bool, name: string){
         tab[address]$a +=1;
         if(address in tab){
                 if(tab[address]$b != value)
                                 {
                                 #print "new value for same address";
                                 if(network_time() - tab[address]$t < 1min){
                                         tab[address]$c +=1 ;
                                         print tab[address]$c;
                                         if( |tab[address]$c / tab[address]$a| > 0.1 ){
                                                 NOTICE([$note=Possible_Steganography,
							 $ts=network_time(),
                                                         $msg = "Possible steganography",
                                                         $sub = name]);
                                                 }
                                         }
                                 else{
                                         tab[address]$c = 0;
                                         tab[address]$b = value;
                                         tab[address]$t = network_time();
                                         tab[address]$a = 0;
                                         }
                                 }
         }
         else{
                 tab[address] = BTC($b = value, $t = network_time(), $c = 0, $a = 0);
         }
}
