use lib '.';
use strict;
use Scripts;
use IO::Select;
use IO::Socket;
use Net::hostent;              # for OO version of gethostbyaddr

sub StartServer();
sub GetTimeofDay();
sub GetDiffTimeofDay($);

my $DataPath = '/var/opt/cprocsp/tmp/';

my $server_port = 1501; #1501
#Данные для передачи клиенту
my $pattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.\n";
#TODO revert to 163840

my $multiply = 1500;
my $data = $pattern x $multiply;
my $Client_count = 1; 
my $timeout_cycle = 45;

my $Server_PID = $DataPath.'stunnel_serv.pid';
my $Time_Hires_enable;

{
    eval 'use Time::HiRes';
    $Time_Hires_enable = !$@;
    
    StartServer();
    
    #убить сервер stunnel
    
    print "Take stunnel server PID file from: " . $Server_PID;   
    local *IN;
    if(open (IN, '<'.$Server_PID)){
        my $ln = <IN>;
        if ($ln =~ /\d/) {
            RunCmd('kill', '/bin/kill -s KILL '.$ln); 
        } 
        close IN;
    }
    else {
        print 'Can not open PID file: '.$Server_PID;
    }
    
    
    if(-e '/var/opt/cprocsp/tmp/.stunnelsrv'){
    	RunCmd('rm', 'rm /var/opt/cprocsp/tmp/.stunnelsrv');
    }
    my $srv_conf = $DataPath . 'stunnelsrv.conf';
    my $srv_log = $DataPath . 'stunnel_serv.log';
    
    open(my $FL, '<' . $srv_conf) or print "Can not open for reading \n";
    my $body = '';
    {local $/ = undef; $body = <$FL>; }
    close $FL;
    my $has_auth = 0;
    if ($body =~ m/verify\s*\=\s*(\d)/i) {
		my $verify_level = int($1);
		$has_auth = 1 if ($verify_level > 1);
	}
	
	if ($has_auth) {
		open(my $FL, '<' . $srv_log) or print "Can not open for reading \n";
		my $body = '';
		{local $/ = undef; $body = <$FL>; }
		close $FL;
		my $msg_suffix = "\n" . $srv_conf . "\n" . $srv_log;
		if ($body =~ m/verify\s+ok/i) {
			print "Successfull authentication:" . $msg_suffix . "\n";
                        exit 0;
		}
		else {
			RunCmd("Cat", 'cat ' . $srv_log);
			print "Authentication marker not found:" . $msg_suffix . "\n";
		}
	}
        exit 1;
}


#-----------------------------------------------------------------------------
# Запускает сервер для сетевого обмена
sub StartServer() 
{   
    my $datalength;
    my $difftime;
    my $send_speed = 0;
    my $start_time;    
    my $receive_speed = 0;        
    my $count=0;
                   # pick something not in use
    my $server = IO::Socket::INET->new( Proto     => 'tcp',
                                        LocalPort => $server_port,
                                        Listen    => SOMAXCONN,
                                        Reuse     => 1);
    unless ($server) {
        print "can't setup server : ". $!;
        return 1 
    }
    print ("[Server $0 accepting clients on port ".$server_port."]\n");
    my $stop = 0;
    my $sel = new IO::Select($server);
    while (1) 
    {
        #ожидаем подключения
        my @clients = $sel->can_read(1);
        if (scalar @clients == 0) {
            $stop++;
            if ($stop >= $timeout_cycle)
            {     
                if ($count == 0)
                {
                    print "Timeout. No clients connected. Server shuts."; 
                }else
                {
                    print "Timeout. $count clients was connected. Server shuts.";
                }           
                last;
            } 
            next;
        }
        my $client = $server->accept();
        $count++;
        $client->autoflush(1);
        
        #для проверки на дисконнект       
        #close $client; 
        #last;
        
        
        my @job_time = localtime();        
        my $str = sprintf("%02d:%02d:%02d Client: " . $client->peerhost() . "\n", $job_time[2], $job_time[1], $job_time[0]);
        print ("$str\n"); 
                
        #время начала отправки данных
        $start_time = GetTimeofDay(); 
        
        #отправляем данные
        
        my $PIPE_ERR = 0;            
        #перехватываем SIGPIPE (broken pipe) 
        $SIG{PIPE} = sub {$PIPE_ERR = 1};
        eval{       
            print $client "SEND: \n";
            print $client $data;
	    #rtLog('Server send:'.'SEND: \n'.$data.'END.\n');
            print $client "END.\n";
        };        
        if($@)
        {
            print "Error while sending data: " . $@;
            close $client;
            last;
        }
        if($PIPE_ERR == 1)
            {
                print "Broken pipe error.";
                close $client;
                last;                
            }
        #$client->flush();
        
        #замеряем время отправки
        $datalength = length($data);
        $difftime = GetDiffTimeofDay($start_time);
        if ($difftime > 0) { $send_speed = $datalength / ($difftime ) }; 
        my $logstr = sprintf("Sent %d bytes of data, %5.2f Mb/sec.",
            $datalength,$send_speed/(1024*1024));
        print $logstr;
        
        #время начала приёма данных
        $start_time = GetTimeofDay();
                
        my $line;
        my $r_data;
        my $correct_start = 0;
        my $correct_finish = 0;        
        while ($line = <$client>) {                      
            if ($correct_start == 1) {                        
                if ($line =~ m/END.\n/i) {
                    $correct_finish = 1;
                    last;
                }
		$r_data .= $line;  
		#rtLog('Server get line: '.$line);  
            }
            else {
                if ($line =~ m/SEND\:\s.*/i) { $correct_start = 1 } 
                else { last }                  
            }                                 
        }
	#rtLog('Server get back: '.$r_data);
        if ($correct_start) {
            print 'Socket error: ' . $! if (!$correct_finish);
            $difftime = GetDiffTimeofDay($start_time);
            $datalength = length($r_data);     
            if ( $difftime > 0 ) { $receive_speed = $datalength / ($difftime ) };                           
            my $totalspeed = ( $receive_speed + $send_speed )/(2 * 1024 * 1024);
            $logstr = sprintf ("Received %d bytes of data, %5.2f Mb/sec. The total data rate is %5.2f Mb/sec",
                $datalength, $receive_speed/(1024*1024), $totalspeed);
            print ($logstr);              
        }
        if ($correct_start and $correct_finish and $r_data ne $data) {
            print ("Transfer error. Received: ".length($r_data)." bytes:\n".$r_data.
                substr ($r_data, 0, length($pattern) + 10) . "\n...");                     
        }
         
        close $client;

        if ($Client_count <= $count)
        {
            print ("All $Client_count clients were connected. Server shuts.");
            last;
        }  
    }
    return 0;
}
sub GetTimeofDay()
{
    if ($Time_Hires_enable)
    { 
        my ($sec, $usec) = Time::HiRes::gettimeofday();
        my $time = $sec + ($usec) * 0.000001;  
        return $time;
    } 
}
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
__END__
