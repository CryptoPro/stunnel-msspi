use lib '.';
use strict;
use Scripts;

print "\n\n--------MAKE DEFAULT CERTS--------\n";
print "----------------------------------\n\n";

print "perl make_default_certs.pl:\n\n";
my $rc = system("perl make_default_certs.pl");
if ($rc != 0)
{
    die 1;
}

sleep(1);

print "\n\n--------START STUNNEL-------------\n";
print "----------------------------------\n\n";

print "perl stunnel.pl local:\n\n";
$rc = system("perl stunnel.pl local");
if ($rc != 0)
{
    die 1;
}

sleep(1);

print "\n\n--------START CLIENT--------------\n";
print "----------------------------------\n\n";

print "perl stunnel_client.pl local > client_log &:\n\n";
$rc = system("perl stunnel_client.pl local > client_log &");
if ($rc != 0)
{
    die 1;
}

sleep(1);

print "\n\n--------START SERVER--------------\n";
print "----------------------------------\n\n";

print "perl stunnel_server.pl:\n\n";
$rc = system("perl stunnel_server.pl");
if ($rc != 0)
{
    die 1;
}

sleep(3);

print "\n\n--------CLIENT LOG----------------\n";
print "----------------------------------\n\n";

print "cat client_log:\n\n";
$rc = system("cat client_log");
if ($rc != 0)
{
    die 1;
}

print "\n\n--------CLIENT STUNNEL LOG--------\n";
print "----------------------------------\n\n";

print "cat /var/opt/cprocsp/tmp/stunnel_cli.log:\n\n";
$rc = system("cat /var/opt/cprocsp/tmp/stunnel_cli.log");
if ($rc != 0)
{
    die 1;
}

print "\n\n--------SERVER STUNNEL LOG--------\n";
print "----------------------------------\n\n";

print "cat /var/opt/cprocsp/tmp/stunnel_serv.log:\n\n";
$rc = system("cat /var/opt/cprocsp/tmp/stunnel_serv.log");
if ($rc != 0)
{
    die 1;
}

#  Check if stunnel_client.pl found error
die 1 if -e ".is_error";
