use lib '.';
use strict;
use Scripts;
use IO::Select;
use IO::Socket;

sub ConnectToThisServer($$);
sub ConnectToRemoteServer($$);
sub GetTimeofDay();
sub GetDiffTimeofDay($);

my $DataPath = '/var/opt/cprocsp/tmp/';

my $client_port = 1502;
my $timeout_cycle = 45;
my $Client_PID = $DataPath.'stunnel_cli.pid';
my $Time_Hires_enable;
my $cert_CN_value;

{
    my $mode = 'local';
    
    if (scalar @ARGV) {
        if    ($ARGV[0] =~ m/local/i) { $mode = 'local' }
        elsif ($ARGV[0] =~ m/remote/i) { $mode = 'remote' }
    }    

    eval 'use Time::HiRes';
    $Time_Hires_enable = !$@;
    
    if ($mode eq 'local') {
        ConnectToThisServer("localhost", $client_port);
    }
    elsif ($mode eq 'remote') {
        ConnectToRemoteServer("localhost", $client_port);
    }
    
    print "Take stunnel client PID file from: " . $Client_PID. "\n";   
    
    
    local *IN;
    if (open (IN, '<'.$Client_PID)){
        my $ln = <IN>;
        close IN;
        if ($ln =~ /\d/) {
            sleep(1);
            RunCmd('kill', '/bin/kill -s KILL '.$ln); 
        } 
    }
    else {
        print "Can not open PID file: ".$Client_PID. "\n";
    }

    my $cln_conf = $DataPath . 'stunnelcln.conf';
    my $cln_log = $DataPath . 'stunnel_cli.log';
    
    open(my $FL, '<' . $cln_conf) or print "Can not open for reading \n";
    my $body = '';
    {local $/ = undef; $body = <$FL>; }
    close $FL;
    my $has_auth = 0;
    if ($body =~ m/verify\s*\=\s*(\d)/i) {
		my $verify_level = int($1);
		$has_auth = 1 if ($verify_level > 1);
	}
	
	if ($has_auth) {
		open(my $FL, '<' . $cln_log) or print "Can not open for reading \n";
		my $body = '';
		{local $/ = undef; $body = <$FL>; }
		close $FL;
		my $msg_suffix = "\n" . $cln_conf . "\n" . $cln_log;
		if ($body =~ m/verify\s+ok/i) {
			print "Successfull authentication:" . $msg_suffix . "\n";
                        exit 0;
		}
		else {
			print "Authentication marker not found:" . $msg_suffix . "\n";
		}
	}
	open (my $FL, '>', ".is_error");
	close $FL;
}


#-----------------------------------------------------------------------------
# —оедин€етс€ с машиной из пула (еЄ сервером: см. StartServer())
sub ConnectToThisServer($$) 
{
    my $datalength;
    my $difftime;
    my $send_speed = 0;    
    my $str_speed;
    my $str_length;
    my $receive_speed = 0;   
    my $start_time;   
    
    my $host = shift || 'localhost';
    my $port = shift || $client_port;
    print "Connecting to server $host on port $port \n";
    my $receivedata = 0;
    my $i;
    for ($i = 0; $i < $timeout_cycle; $i++) {
        my $nexttry = 1; 	    
        my $remote = IO::Socket::INET->new( Proto     => "tcp",
                                            PeerAddr  => $host,
                                            Timeout   => 1,
                                            PeerPort  => $port,
                                           );
                                           
        if (!$remote) {
            print "Can not connect $host on port $port : " . $! . "\n";
            sleep(1);
            next;
        } 
        #$remote->autoflush(1);	         
        $start_time = GetTimeofDay();
           
        #принимаем данные
        my $line;
        my $r_data = '';
        my $correct_start = 0;
        my $correct_finish = 0;        
        while ($line = <$remote>) {
            if ($correct_start == 1) {                        
                if ($line =~ m/END.\n/i) {
                    $correct_finish = 1;
                    last;
                }
                $r_data .= $line;
		#rtLog('Client get line: '.$line);      
            }
            else {
                if ($line =~ m/SEND\:\s.*/i) { $correct_start = 1 } 
                else { last }                  
            }                                 
        }
        if ($correct_start) {
            print 'Socket error: ' . $! . "\n" if (!$correct_finish);
            $difftime = GetDiffTimeofDay($start_time);
            print "Connected to server $host on port $port \n"; 
            $datalength = length($r_data);     
            if ($difftime > 0) { $receive_speed = $datalength / ($difftime ) };
            my $logstr = sprintf("Received %d bytes of data, %5.2f Mb/sec.",
                $datalength,$receive_speed/(1024*1024));
            print $logstr . "\n";
            $nexttry = 0;            
        }
	#rtLog('Client get it: '.$r_data.' and send back.');
        if ($correct_start and $correct_finish) { 
            #отправл€ем данные
            $start_time = GetTimeofDay();  
           
            my $PIPE_ERR = 0;            
            $SIG{PIPE} = sub {$PIPE_ERR = 1};
            eval {
                print $remote "SEND: \n";
                print $remote $r_data;
                print $remote "END.\n";
            };
            if ($@) {
                print "Error while sending data: " . $@ . "\n";
                sleep(1);
                close $remote;
                last;
            }            
            if ($PIPE_ERR == 1) {
                print "Broken pipe error. \n";
                sleep(1);
                close $remote;
                last;                
            }
            #замер€ем врем€ отправки
            $datalength = length($r_data);
            $difftime = GetDiffTimeofDay($start_time);
            if ($difftime > 0) { $send_speed = $datalength / ($difftime ) }; 
            my $logstr = sprintf("Sent %d bytes of data, %5.2f Mb/sec.",
                $datalength,$send_speed/(1024*1024));
            print $logstr;
        }
        else {
            print "Disconnect with message : $! \n";
            # разрыв соединени€. попробуем подключитьс€ еще раз          
        }                                                    
        
    	close $remote;
        if ($nexttry == 0) {
    	    #работа завершена 
    	    last;   
    	}
    	else {
    	    #подождем немного перед следующей попыткой    	    
    	    sleep(1);
    	}
    }
    print "Timeout when connecting $host on port $port : " . $! . "\n" if ($i == $timeout_cycle);
    exit 1;
}


#-----------------------------------------------------------------------------
sub GetTimeofDay()
{
    if ($Time_Hires_enable)
    { 
        my ($sec, $usec) = Time::HiRes::gettimeofday();
        my $time = $sec + ($usec) * 0.000001;  
        return $time;
    } 
}

#-----------------------------------------------------------------------------
sub GetDiffTimeofDay($)
{
    my $beg_time = shift;  
    my $difftime=0;
    if ($Time_Hires_enable)
    {        
       my ($sec, $usec) = Time::HiRes::gettimeofday();                  
       $difftime = ($sec + ($usec ) * 0.000001)-$beg_time;               
    }
    return $difftime;
}

#-----------------------------------------------------------------------------
sub ParserGetCertCN($) {
    $cert_CN_value = '';
    if (scalar @_ <= 0) {
        print ("Parser call without argument.");
        return 1;
    }
    my $all = $_[0];
    my @sp = split /\n/, $all;
    foreach my $ln (@sp) {
        if ($ln =~ m/(CN=[^,]+)/){
            $cert_CN_value = $1;
        }
    }
    if ($cert_CN_value eq '') {
        return 'Cert CN not found';
    }
    return 0;
}

#-----------------------------------------------------------------------------
# TODO: плоха€ функци€, нарушающа€ инкапсул€цию (много знает про сертификат из stunnel.pl)


#-----------------------------------------------------------------------------
sub ConnectToRemoteServer($$) {
    my $server = shift;
    my $port = shift;
    my $url = 'http://' . $server . ':' . $port . '/'; 
    my @cases = (
        {
            file => 'test.htm',
            auth_cln => 0,
            server_algs => ['GOST94_256'],
        },
        {
            file => 'allow.htm',
            auth_cln => 1,
            server_algs => ['GOST94_256'],
        },
        {
            file => 'auth.htm',
            auth_cln => 1,
            server_algs => ['GOST94_256'],
        },
    );

    foreach my $case (@cases) {
        if ($case->{auth_cln} == 0) {
            my $file = $case->{file};
            if (RunCmd("curl_or_wget_CRL", "curl - o '${file}' '${url}' 
				|| wget -t 1 -O '${file}' '${url}' ") == 0) {
                print 'Successfully got: ' . $url . $file;
            }
            else {
                print 'Failed to get: ' . $url . $file;
            }
        }
        else {
			my $file = $case->{file};
			print "Need CanWorkWithAuth \n";
			if (RunCmd("curl_or_wget_CRL", "curl - o '${file}' '${url}' 
				|| wget -t 1 -O '${file}' '${url}' ") == 0) {
                print 'Successfully got: ' . $url . $file;
            }
            else {
                print 'Failed to get: ' . $url . $file;
            }
		}
    } 
}

#-----------------------------------------------------------------------------
__END__
