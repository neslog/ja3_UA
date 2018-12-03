# Requirements:   requires JA3 package
#                 Bro must listen on both sides of a proxy.  One side is TLS other side is clear text.
#
# This will keep track of the orig_h and JA3 on the TLS side of a proxy.
#

module JA3;

export {
global https_conns: table[addr] of string &redef;
}

@if ( Version::at_least("2.6") || ( Version::number == 20500 && Version::info$commit >= 944 ) )
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=1
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=1
@endif
{
https_conns[c$id$orig_h] = c$ssl$ja3;
}
