use lib '.';
use strict;
use Scripts;

sub _RunCmd($$);

my $DataPath = "/var/opt/cprocsp/tmp/";
my $DsrfPath = "/var/opt/cprocsp/dsrf";
my $CproPath = "/opt/cprocsp";

my $arch_suffix;

if (defined $ENV{'CPRO_SUFFIX'})
{
    $arch_suffix = $ENV{'CPRO_SUFFIX'}; 
}
else
{
    $arch_suffix = 'amd64';
}

my $cpconfig = $CproPath . "/sbin/" . $arch_suffix . "/cpconfig";
my $cryptcp = $CproPath . "/bin/" . $arch_suffix . "/cryptcp";
my $csptest = $CproPath . "/bin/" . $arch_suffix . "/csptest";
my $certmgr = $CproPath . "/bin/" . $arch_suffix . "/certmgr";


#-----------------------------------------------------------------------------
{
    RunCmd("DelCert", $cryptcp . ' -delcert -m -yes -dn CN= -nochain');
    RunCmd("DelCert", $cryptcp . ' -delcert -u -yes -dn CN= -nochain');
    RunCmd("DelCert", $csptest . ' -notime -noerrorwait -keyset -silent -deletekeyset -pattern "" -verifyco -provtype 81');
    RunCmd("DelCert", $csptest . ' -notime -noerrorwait -keyset -silent -deletekeyset -pattern "" -verifyco -provtype 81 -machinekeyset');
    
    #delete ssl certs and keys
    _RunCmd('DelCertRSA', 'rm ' . $DataPath . 'stunnelsrvRSA.cer') if (-e $DataPath . 'stunnelsrvRSA.cer');
    _RunCmd('DelCertRSA', 'rm ' . $DataPath . 'stunnelclnRSA.cer') if (-e $DataPath . 'stunnelclnRSA.cer');
    _RunCmd('DelKeyRSA', 'rm ' . $DataPath . 'stunnelsrvRSA.key') if (-e $DataPath . 'stunnelsrvRSA.key');
    _RunCmd('DelKeyRSA', 'rm ' . $DataPath . 'stunnelclnRSA.key') if (-e $DataPath . 'stunnelclnRSA.key');

    _RunCmd('DelCertPem', 'rm ' . $DataPath . 'stunnelcln.pem') if (-e $DataPath . 'stunnelcln.pem');
    _RunCmd('DelCertPem', 'rm ' . $DataPath . 'stunnelsrv.pem') if (-e $DataPath . 'stunnelsrv.pem');

    #make RSA certs
    _RunCmd('MakeCertAndKeyRSA', 'openssl req -x509 -newkey rsa:2048 -keyout ' . $DataPath . 'stunnelsrvRSA.key -nodes -out ' . $DataPath . 'stunnelsrvRSA.cer -subj \'/CN=srvRSA/C=RU\' ');
    _RunCmd('MakeCertAndKeyRSA', 'openssl rsa -in ' . $DataPath . 'stunnelsrvRSA.key -out ' . $DataPath . 'stunnelsrvRSA.key');

    _RunCmd('MakeCertAndKeyRSA', 'openssl req -x509 -newkey rsa:2048 -keyout ' . $DataPath . 'stunnelclnRSA.key -nodes -out ' . $DataPath . 'stunnelclnRSA.cer -subj \'/CN=clnRSA/C=RU\' ');
    _RunCmd('MakeCertAndKeyRSA', 'openssl rsa -in ' . $DataPath . 'stunnelclnRSA.key -out ' . $DataPath . 'stunnelclnRSA.key');
    
    #make GOST certs
    _RunCmd('MakeDSRF', $cpconfig . " -hardware rndm -add cpsd -name 'cpsd rng' -level 2 ");
    _RunCmd('MakeDSRF', $cpconfig . " -hardware rndm -configure cpsd -add string /db1/kis_1 " . $DsrfPath . "/db1/kis_1");
    _RunCmd('MakeDSRF', $cpconfig . " -hardware rndm -configure cpsd -add string /db2/kis_1 " . $DsrfPath . "/db2/kis_1");
    _RunCmd('MakeDSRF', "cp ./mydsrf " . $DsrfPath . "/db1/kis_1");
    _RunCmd('MakeDSRF', "cp ./mydsrf " . $DsrfPath . "/db2/kis_1");
    if ($arch_suffix eq "arm" || $arch_suffix eq "aarch64")
    {
        # работаем в другим dsrf, который должен быть установлен
        _RunCmd('DisableDsrf', $cpconfig . " -hardware rndm -del cpsd");
    }
    #_RunCmd('Restart csp-daemon', "/etc/init.d/cprocsp restart");
    
    #new certs
    _RunCmd('MakeCertGOST', $cryptcp . " -creatcert -provtype 81 -silent -rdn \'CN=127.0.0.1\' -cont \'\\\\.\\HDIMAGE\\localhost_cont\' -certusage 1.3.6.1.5.5.7.3.1 -km -dm -ex -ca http://testgost2012.cryptopro.ru/certsrv -enable-install-root");
    _RunCmd('MakeCertGOST', $cryptcp . " -creatcert -provtype 81 -silent -rdn \'E=cln512ecryptopro.ru, CN=cln512e\' -cont \'\\\\.\\HDIMAGE\\cln512e\' -certusage 1.3.6.1.5.5.7.3.2 -km -dm -both -ca http://testgost2012.cryptopro.ru/certsrv -enable-install-root");
 
    #old certs (могут быть ошибки из-за упоминания о старых сертификатах)
    #_RunCmd('MakeCertGOST', "/opt/cprocsp/bin/amd64/cryptcp -creatcert -provtype 75 -provname 'Crypto-Pro GOST R 34.10-2001 KC1 CSP'  -silent -rdn \'CN=127.0.0.1\' -cont \'\\\\.\\HDIMAGE\\localhost_cont\' -certusage 1.3.6.1.5.5.7.3.1 -km -dm -ex -ca http://testgost2012.cryptopro.ru/certsrv -keysize 512 -hashalg 1.2.643.2.2.9 -enable-install-root");
    #_RunCmd('MakeCertGOST', "/opt/cprocsp/bin/amd64/cryptcp -creatcert -provtype 75 -provname 'Crypto-Pro GOST R 34.10-2001 KC1 CSP'  -silent -rdn \'E=cln512ecryptopro.ru, CN=cln512e\' -cont \'\\\\.\\HDIMAGE\\cln512e\' -certusage 1.3.6.1.5.5.7.3.2 -km -dm -both -ca http://testgost2012.cryptopro.ru/certsrv -keysize 512 -hashalg 1.2.643.2.2.9 -enable-install-root");
    
    #export certs
    _RunCmd('Safe cert in '.$DataPath, $certmgr . " -export -cert -dest " . $DataPath . "stunnelsrv.cer -dn CN=127.0.0.1 -store mmy");
    _RunCmd('Safe cert in '.$DataPath, $certmgr . " -export -cert -dest " . $DataPath . "stunnelcln.cer -dn CN=cln512e -store mmy");

    _RunCmd('Make cert PEM format in '.$DataPath, "openssl x509 -inform DER -in " . $DataPath . "stunnelcln.cer -out " . $DataPath . "stunnelcln.pem");
    _RunCmd('Make cert PEM format in '.$DataPath, "openssl x509 -inform DER -in " . $DataPath . "stunnelsrv.cer -out " . $DataPath . "stunnelsrv.pem");
}

sub _RunCmd($$)
{
    my $rv = RunCmd(shift, shift);
    if ($rv != 0)
    {
        die $rv;
    }
}


__END__
