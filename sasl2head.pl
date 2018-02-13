#!/usr/bin/perl

use Sys::Syslog qw(:DEFAULT setlogsock);
use IO::Socket;
use Mail::SPF;
use Socket;
use Sys::Hostname;

$syslog_socktype = 'unix'; 
$syslog_facility = 'mail';
$syslog_options  = 'pid';
$syslog_priority = 'info';

#$verbose="1";

sub fatal_exit {
    my($first) = shift(@_);
    syslog "err", "fatal: $first", @_;
    exit 1;
}

sub smtpd_access_policy {
        my $YOURSITE_client_address=$attr{"client_address"};
        my $YOURSITE_sasl_username=$attr{"sasl_username"};
	my $YOURSITE_helo_name=$attr{"helo_name"};
	my $YOURSITE_sender=$attr{"sender"};
	if (($YOURSITE_sasl_username ne "") and ( $YOURSITE_sender ne "")) {
	    my $fqdn = (hostname);
	    my $addr = inet_ntoa((gethostbyname($fqdn))[4]);
	    my $YOURSITE_cipher=$attr{"encryption_cipher"} ;
	    my $YOURSITE_protocol=$attr{"encryption_protocol"};
	    my $YOURSITE_client_name=$attr{"client_name"};
	    my $request     = Mail::SPF::Request->new(
		versions        => [1, 2],              # optional
		scope           => 'mfrom',             # or 'helo', 'pra'
		identity        => $YOURSITE_sender,
		ip_address      => $addr,
		helo_identity   => $fqdn   # optional
		);
	    my $result      = $spf_server->process($request);
	    my $result_code = $result->code;
	    syslog $syslog_priority, "header prepend X-YOURSITE-Auth: $YOURSITE_sasl_username [$YOURSITE_client_address] $YOURSITE_helo_name $YOURSITE_sender $result_code $YOURSITE_client_name $YOURSITE_cipher $YOURSITE_protocol";
            if ($result_code ne "pass"){
                $verbose="1";
                syslog $syslog_priority, "$YOURSITE_sasl_username, tried to send an email with invalid spf sender";
		return  "defer_if_permit $YOURSITE_sasl_username, invalid spf for sender";
	    }
	    elsif ($result_code eq "pass"){
		if (($YOURSITE_helo_name eq "suspicioushelostring") and ($YOURSITE_client_name eq "unknown")){
		    syslog $syslog_priority, "$YOURSITE_sasl_username, very phishy";
		    return  "defer_if_permit $YOURSITE_sasl_username, contact helpdesk to sort this out";
		}
	    }
	} 
        return "PREPEND X-YOURSITE-Auth: $YOURSITE_sasl_username [$YOURSITE_client_address]" unless $YOURSITE_sasl_username eq "";
}

setlogsock $syslog_socktype;
openlog 'sasl2head', $syslog_options, $syslog_facility;

select((select(STDOUT), $| = 1)[0]);

$spf_server  = Mail::SPF::Server->new();

while (<STDIN>) {
    if (/([^=]+)=(.*)\n/) {
        $attr{substr($1, 0, 512)} = substr($2, 0, 512);
    } elsif ($_ eq "\n") {
        fatal_exit "unrecognized request type: '%s'", $attr{request} unless $attr{"request"} eq "smtpd_access_policy";
        $action = smtpd_access_policy();
        if ($verbose) {
            for (keys %attr) {
                syslog $syslog_priority, "Attribute: %s=%s", $_, $attr{$_};
            }
        }
        syslog $syslog_priority, "Action: %s", $action if $verbose;
        print STDOUT "action=$action\n\n";
        %attr = ();
    } else {
        chop;
        syslog $syslog_priority, "warning: ignoring garbage: %.100s", $_;
    }
}
