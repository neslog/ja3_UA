#
# This script will look at the X-FORWARDED-FOR header and lookup the IP in the HTTPS_Conns
#   Note: X-FORWARDED-FOR may contain multipe IPs.  TODO: take length of  X-FORWARDED-FOR and take first IP of the chain as orig_h.
#

module HTTP;

redef record HTTP::Info += {
	ja3: 	string &log	&optional;
};

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
{
if ( name == "X-FORWARDED-FOR" ) {
# lookup conneciton in https_conns;
if ( to_addr(value) in JA3::https_conns ) {
  #print JA3::https_conns[to_addr(value)];
  c$http$ja3 = JA3::https_conns[to_addr(value)];
  delete JA3::https_conns[to_addr(value)];
  }
 }
}
