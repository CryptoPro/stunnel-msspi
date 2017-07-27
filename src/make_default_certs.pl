##############################################################################
# Проверка работы CSP с помощью csptest и CryptCP
# ____________________________________________________________________________
#
# Платформы: Windows, Unix
# ____________________________________________________________________________
#
# Провайдеры: CSP 2.0, CSP 2.1 (Phoenix), MSBase, DSS.
# ____________________________________________________________________________
#
# Для правильной работы необходимо:
# - наличие файлов @files
# - наличие стандарных сертификатов
##############################################################################

#=============================================================================
# Создаёт набор сертификатов и контейнеров, используемых для тестов
# Предварительно удаляет сущетствующие с такими же именами
#
# Пока контейнеры создаются "по сертификатам": отличие в том, что не знаешь,
# где должен храниться контейнер. Пока считаем, что \\.\REGISTRY\ или \\.\HDIMAGE\
#=============================================================================

use strict;

my $DataPath = '/var/opt/cprocsp/tmp/';

sub RunCmd($$) {
    print "\n+++++++++++++++++++++++++++++++++\n";
    my $info = shift;
    my $cmd = shift;
    print $info.": \n";
    print $cmd." \n\n";
    my $res = system($cmd);
    print $res." \n\n";
    print "+++++++++++++++++++++++++++++++++ \n\n\n";
    return $res;
}

sub DisableInstallCertWindow($);

#-----------------------------------------------------------------------------
{
    system('mkdir /var/opt/cprocsp/tmp');
	
    my $cryptcp = '/opt/cprocsp/bin/amd64/cryptcp';
    my $csptest = '/opt/cprocsp/bin/amd64/csptest';
    
    #RunCmd("DelCert", $cryptcp . ' -delcert -m -yes -dn CN= -nochain');
    #RunCmd("DelCert", $cryptcp . ' -delcert -u -yes -dn CN= -nochain');
    RunCmd("DelCert", $csptest . ' -notime -noerrorwait -keyset -silent -deletekeyset -pattern "" -verifyco -provtype 75 -provider "Crypto-Pro GOST R 34.10-2001 KC1 CSP" ');
    
    #delete ssl certs and keys
    if (-e $DataPath . 'stunnelsrvRSA.cer'){
        RunCmd('DelCertRSA', 'rm ' . $DataPath . 'stunnelsrvRSA.cer');
        RunCmd('DelCertRSA', 'rm ' . $DataPath . 'stunnelclnRSA.cer');
        RunCmd('DelKeyRSA', 'rm ' . $DataPath . 'stunnelsrvRSA.key');
        RunCmd('DelKeyRSA', 'rm ' . $DataPath . 'stunnelclnRSA.key');
    }

    #make RSA certs

    RunCmd('MakeCertAndKeyRSA', 'openssl req -x509 -newkey rsa:2048 -keyout ' . $DataPath . 'stunnelsrvRSA.key -nodes -out ' . $DataPath . 'stunnelsrvRSA.cer -subj \'/CN=srvRSA/C=RU\' ');
    RunCmd('MakeCertAndKeyRSA', 'openssl rsa -in ' . $DataPath . 'stunnelsrvRSA.key -out ' . $DataPath . 'stunnelsrvRSA.key');

    RunCmd('MakeCertAndKeyRSA', 'openssl req -x509 -newkey rsa:2048 -keyout ' . $DataPath . 'stunnelclnRSA.key -nodes -out ' . $DataPath . 'stunnelclnRSA.cer -subj \'/CN=clnRSA/C=RU\' ');
    RunCmd('MakeCertAndKeyRSA', 'openssl rsa -in ' . $DataPath . 'stunnelclnRSA.key -out ' . $DataPath . 'stunnelclnRSA.key');
    
    #make GOST certs
    RunCmd('MakeDSRF', "/opt/cprocsp/sbin/amd64/cpconfig -hardware rndm -add cpsd -name 'cpsd rng' -level 2 ");
    RunCmd('MakeDSRF', "/opt/cprocsp/sbin/amd64/cpconfig -hardware rndm -configure cpsd -add string /db1/kis_1 /var/opt/cprocsp/dsrf/db1/kis_1");
    RunCmd('MakeDSRF', "/opt/cprocsp/sbin/amd64/cpconfig -hardware rndm -configure cpsd -add string /db2/kis_1 /var/opt/cprocsp/dsrf/db2/kis_1");
    RunCmd('MakeDSRF', "cp ./mydsrf /var/opt/cprocsp/dsrf/db1/kis_1");
    RunCmd('MakeDSRF', "cp ./mydsrf /var/opt/cprocsp/dsrf/db2/kis_1");
    
    


    RunCmd('MakeCertGOST', "/opt/cprocsp/bin/amd64/cryptcp -creatcert -provtype 75 -provname 'Crypto-Pro GOST R 34.10-2001 KC1 CSP'  -silent -rdn \'CN=127.0.0.1\' -cont \'\\\\.\\HDIMAGE\\localhost_cont\' -certusage 1.3.6.1.5.5.7.3.1 -ku -du -ex -ca http://cryptopro.ru/certsrv -keysize 512 -hashalg 1.2.643.2.2.9 -enable-install-root");
    RunCmd('MakeCertGOST', '/opt/cprocsp/bin/amd64/cryptcp -creatcert -provtype 75 -provname "Crypto-Pro GOST R 34.10-2001 KC1 CSP"  -silent -rdn \'E=cln512e@cryptopro.ru, CN=cln512e\' -cont \'\\\\.\\HDIMAGE\\cln512e\' -certusage 1.3.6.1.5.5.7.3.2 -ku -du -both -ca http://cryptopro.ru/certsrv -keysize 512 -hashalg 1.2.643.2.2.9 -enable-install-root')
    

}


__END__
