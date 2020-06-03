redef enum Notice::Type += { Possible_Steganography };
redef Weird::actions: table[string] of Weird::Action += {
         ["Possible_Steganography"] = Weird::ACTION_NOTICE,
};

type VTC: record {
    v: int;
    t: time;
    c: count;
};


type STC: record {
    s: string;
    t: time;
    c: count;
};

type ITC: record {
     i: interval;
     t: time;
     c: count;
};

type BTC: record {
     b: bool;
     t: time;
     c: count;
};

type IAT: record {
     c: count;
     v: vector of interval;
     t: time;
};

function check_freqency(tab: table[addr] of STC, address: addr, value: string, name: string, period: interval &default=1min, threshold: int &default=10){
        if(address in tab){
		print tab[address]$s;
		print value;
                if(tab[address]$s != value)
                                {
                                #print "new value for same address";
                                if(network_time() - tab[address]$t < period){
                                        tab[address]$c +=1 ;
                                        print tab[address]$c;
                                        if(tab[address]$c >= threshold){
                                                NOTICE([$note=Possible_Steganography,
                                                        $msg = "Possible steganography",
                                                        $sub = name]);
                                                }
                                        }
                                else{
                                        tab[address]$c = 0;
                                        tab[address]$s = value;
                                        tab[address]$t = network_time();
                                        }
                                }
        }
        else{
                tab[address] = STC($s = value, $t = network_time(), $c = 0);
        }
}

function check_freqency_t(tab: table[addr] of ITC, address: addr, value: interval, name: string){
         if(address in tab){
                 if(tab[address]$i != value)
                                 {
                                 #print "new value for same address";
                                 if(network_time() - tab[address]$t < 1min){
                                         tab[address]$c +=1 ;
                                         print tab[address]$c;
                                         if(tab[address]$c >= 10){
                                                 NOTICE([$note=Possible_Steganography,
                                                         $msg = "Possible steganography",
                                                         $sub = name]);
                                                 }
                                         }
                                 else{
                                         tab[address]$c = 0;
                                         tab[address]$i = value;
                                         tab[address]$t = network_time();
                                         }
                                 }
         }
         else{
                 tab[address] = ITC($i = value, $t = network_time(), $c = 0);
         }
}

function check_freqency_b(tab: table[addr] of BTC, address: addr, value: bool, name: string){
         if(address in tab){
                 if(tab[address]$b != value)
                                 {
                                 #print "new value for same address";
                                 if(network_time() - tab[address]$t < 1min){
                                         tab[address]$c +=1 ;
                                         print tab[address]$c;
                                         if(tab[address]$c >= 10){
                                                 NOTICE([$note=Possible_Steganography,
                                                         $msg = "Possible steganography",
                                                         $sub = name]);
                                                 }
                                         }
                                 else{
                                         tab[address]$c = 0;
                                         tab[address]$b = value;
                                         tab[address]$t = network_time();
                                         }
                                 }
         }
         else{
                 tab[address] = BTC($b = value, $t = network_time(), $c = 0);
         }
}
