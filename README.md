# phosphor-monitor-hostname
BMC will dynamically generate a self-signed certificate once the new hostname is assigned.

### IPMI assign hostname
ipmitool -H $IP -I lanplus -U root -P 0penBmc -C 17 dcmi set_mc_id_string $hostname

### Get BMC server certificate infomation
echo quit | openssl s_client -showcerts -servername $IP -connect $IP:443
