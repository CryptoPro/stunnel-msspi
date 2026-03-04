##############################################################################
use lib '.';
use strict;
use Scripts;

sub _RunCmd($$);
sub KillStunnels();
sub PrepareAndRunConf($$$$);

my @ParserResult = ();

my $server_host_name = '127.0.0.1';
my $remote_host_name = 'ref-x86-xp'; 
my $tunnel_port = '1500';
my $server_port = '1501';
my $client_port = '1502';
my $remote_port = '443';
my $unix_socket_file = '/var/opt/cprocsp/tmp/.stunnelsrv';
my $DataPath = '/var/opt/cprocsp/tmp/';

my $servercert_file = $DataPath . 'stunnelsrv.cer';
my $clientcert_file = $DataPath . 'stunnelcln.pem';
my $serverconf_file = $DataPath . 'stunnelsrv.conf';
my $clientconf_file = $DataPath . 'stunnelcln.conf';

my $servercert_file_rsa = $DataPath . 'stunnelsrvRSA.cer';
my $clientcert_file_rsa = $DataPath . 'stunnelclnRSA.cer';
my $serverkey_file_rsa = $DataPath . 'stunnelsrvRSA.key';
my $clientkey_file_rsa = $DataPath . 'stunnelclnRSA.key';

my $cln_cert = 'cln512e';
my $srv_cert = '127.0.0.1';

my $cln_cert_rsa = 'clnRSA';
my $srv_cert_rsa = 'srvRSA';


# заполнение конфигураций

# сервер и клиент

my $serverconf_common = 'pid='.$DataPath.'stunnel_serv.pid
output='.$DataPath.'stunnel_serv.log
socket = r:TCP_NODELAY=1
debug = 7
[https]
connect = '.$server_host_name.':'.$server_port;

my $clientconf_common = 'pid='.$DataPath.'stunnel_cli.pid
output='.$DataPath.'stunnel_cli.log
socket = l:TCP_NODELAY=1
debug = 7
[https]
client = yes
accept = '.$server_host_name.':'.$client_port;

#----------------------------

# сервер INET socket
my $serverconf_INET = $serverconf_common.'
cert = '.$servercert_file.'
;socket = l:TCP_NODELAY=1
accept = '.$server_host_name.':'.$tunnel_port.'
verify = 2'; 

# клиент INET socket
my $clientconf_INET = $clientconf_common.'
cert ='.$clientcert_file.'
;socket = r:TCP_NODELAY=1
connect = '.$server_host_name.':'.$tunnel_port.'
verify = 2'; 

#----------------------------

# сервер INET_NO_MSSPI
my $serverconf_INET_NO_MSSPI = $serverconf_common.'
msspi=no
cert = '.$servercert_file_rsa.'
key = '.$serverkey_file_rsa.'
;socket = l:TCP_NODELAY=1
accept = '.$server_host_name.':'.$tunnel_port;
#verify = 2'; 

# клиент INET_NO_MSSPI
my $clientconf_INET_NO_MSSPI = $clientconf_common.'
msspi=no
cert = '.$clientcert_file_rsa.'
key = '.$clientkey_file_rsa.'
;socket = r:TCP_NODELAY=1
connect = '.$server_host_name.':'.$tunnel_port;
#verify = 2'; 

#----------------------------

# сервер UNIX socket
my $serverconf_UNIX = $serverconf_common.'
cert = '.$srv_cert.'
accept = '.$unix_socket_file;

# клиент UNIX socket
my $clientconf_UNIX = $clientconf_common.'
cert ='.$cln_cert.'
connect = '.$unix_socket_file.'
verify = 0';

#----------------------------

# сервер UNIX_NO_MSSPI
my $serverconf_UNIX_NO_MSSPI = $serverconf_common.'
msspi = no
cert = '.$servercert_file_rsa.'
key = '.$serverkey_file_rsa.'
accept = '.$unix_socket_file;

# клиент UNIX_NO_MSSPI
my $clientconf_UNIX_NO_MSSPI = $clientconf_common.'
msspi = no
cert = '.$clientcert_file_rsa.'
key = '.$clientkey_file_rsa.'
connect = '.$unix_socket_file.'
verify = 0';

#----------------------------

# remote config
my $remoteconf_common = 'pid='.$DataPath.'stunnel_cli.pid
output='.$DataPath.'stunnel_cli.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
debug = 7
[https]
client = yes
connect = '.$remote_host_name.':'.$remote_port.'
cert='.$cln_cert;

my $remoteconf_INET = $remoteconf_common.'
accept = '.$server_host_name.':'.$client_port;

my $remoteconf_UNIX = $remoteconf_common.'
accept = '.$unix_socket_file;

#----------------------------

my $stunnel = '../src/stunnel-msspi';


#-----------------------------------------------------------------------------
{
    my $mode = 'local';
    if (scalar @ARGV) {
        if    ($ARGV[0] eq 'local') { $mode = 'local' }
	elsif ($ARGV[0] eq 'local_no_msspi') { $mode = 'local_no_msspi' } #no msspi
        elsif ($ARGV[0] eq 'local_unix') { $mode = 'local_unix' }
	elsif ($ARGV[0] eq 'local_unix_no_msspi') { $mode = 'local_unix_no_msspi' } #no msspi
        elsif ($ARGV[0] eq 'remote') { $mode = 'remote' }
        elsif ($ARGV[0] eq 'remote_unix') { $mode = 'remote_unix' }
        else { rtErr('Bad params') and last } 
    }

    KillStunnels();
    if ($mode eq 'local') {
        PrepareAndRunConf($serverconf_INET, $serverconf_file, 'CN='.$srv_cert, $servercert_file);
        PrepareAndRunConf($clientconf_INET, $clientconf_file, 'CN='.$cln_cert, $clientcert_file);
    }
    elsif ($mode eq 'local_no_msspi') {
        PrepareAndRunConf($serverconf_INET_NO_MSSPI, $serverconf_file, 'CN='.$srv_cert_rsa, 'NO');
        PrepareAndRunConf($clientconf_INET_NO_MSSPI, $clientconf_file, 'CN='.$cln_cert_rsa, 'NO');
    }
    elsif ($mode eq 'local_unix') {
        PrepareAndRunConf($serverconf_UNIX, $serverconf_file, 'CN='.$srv_cert, $servercert_file);
        PrepareAndRunConf($clientconf_UNIX, $clientconf_file, 'CN='.$cln_cert, $clientcert_file);
    }
    elsif ($mode eq 'local_unix_no_msspi') {
        PrepareAndRunConf($serverconf_UNIX_NO_MSSPI, $serverconf_file, 'CN='.$srv_cert_rsa, 'NO');
        PrepareAndRunConf($clientconf_UNIX_NO_MSSPI, $clientconf_file, 'CN='.$cln_cert_rsa, 'NO');
    }
    elsif ($mode eq 'remote') {
        PrepareAndRunConf($remoteconf_INET, $clientconf_file, 'CN='.$cln_cert, $clientcert_file);
    }
    elsif ($mode eq 'remote_unix') {
        PrepareAndRunConf($remoteconf_UNIX, $clientconf_file, 'CN='.$cln_cert, $clientcert_file);
    }

}

#-----------------------------------------------------------------------------

sub PrepareAndRunConf($$$$) {
    my $conf = shift;
    my $conf_file = shift;
    my $cert_dn = shift;
    my $cert_file = shift;
    my $cmd_line = $stunnel.' '.$conf_file;

    local *FL;
    open(FL,"> $conf_file");
    print FL $conf;
    close(FL);

    _RunCmd("Config", "cat " . $conf_file);
    _RunCmd("Start stunnel", $cmd_line);
}

#-----------------------------------------------------------------------------
sub KillStunnels() {

    my $cmd = "ps -A -o pid -o args | grep src/stunnel | grep -v grep || echo ok";
    #_RunCmd("Kill stunnel process", $cmd);
    my $res = `$cmd`;
    Parser($res);
    if (scalar @ParserResult > 0) {
        _RunCmd("Kill stunnel", "/bin/kill -s KILL " . join(' ', @ParserResult));
        sleep(2);
    }
    _RunCmd("Remove logs", "rm " . $DataPath . 'stunnel_serv.log') if (-f $DataPath . 'stunnel_serv.log');
    _RunCmd("Remove logs", "rm " . $DataPath . 'stunnel_cli.log') if (-f $DataPath . 'stunnel_cli.log');
}

#-----------------------------------------------------------------------------
sub _RunCmd($$)
{
    my $rv = RunCmd(shift, shift);
    if ($rv != 0)
    {
        die $rv;
    }
}

#-----------------------------------------------------------------------------
sub Parser($)
{
    my $all = $_[0];  
    my @sp = split /\n/, $all; 
    my $ln;     
    foreach $ln (@sp) {
        if ($ln =~m/\s*(\d+)\s+/i){
            push @ParserResult, $1;
        }    
    }    
    return 0;
}

#-----------------------------------------------------------------------------
__END__
