# sasl2head
Validate spf on outgoing emails on your email server. 
Will catch a lot of people that by accident select the wrong outgoing email server.

You can run it in postfix by adding it to master.cf like this.

sasl2head  unix  -       n       n       -       -       spawn
      user="some low privilege user" argv=/usr/bin/perl /opt/sasl2head/sasl2head.pl

You probaly want to update the time_limit in main.cf
sasl2head_time_limit = 3600s

#You can now validate the session
smtpd_data_restrictions =
                        reject_unauth_pipelining,
                        check_policy_service unix:private/sasl2head,

You can probably do the same in sendmail or some other MTA, please contribute.
