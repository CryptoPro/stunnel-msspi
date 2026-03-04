package Scripts;
BEGIN {

use Exporter ();
@ISA = "Exporter";
@EXPORT = "&RunCmd";

}

sub RunCmd {
    print "\n\n++++++++++++++++CMD-BEGIN+++++++++++++++\n";
    my $info = shift;
    my $cmd = shift;
    print $info.": \n";
    print $cmd." \n\n";
    my $res = system($cmd);
    print "\n\nSystem results: \n" . $res;
    print "\n++++++++++++++++CMD-END+++++++++++++++++\n\n";
    return $res;
}

return 1;
END { }
