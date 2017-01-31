
# all servers
# add an alias to each server that runs logwatch
1) insert into /etc/logwatch/conf/logwatch.conf
MailTo = report@example.com

# mail server only
# configure an inbox to receive a copy of logwatch reports
1) useradd reports
2) insert into /etc/aliases:
report:             reports, root
3) run newaliases
