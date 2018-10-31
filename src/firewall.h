/*
 * Firewall.h
 *
 *      Author: lihaohua
 */

#ifndef SRC_FIREWALL_H_
#define SRC_FIREWALL_H_

#include <string>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <map>
#include <set>
#include <sstream>
#include <algorithm>
using namespace std;

#define DIRECTION_INBOUND "inbound"
#define DIRECTION_OUTBOUND "outbound"
#define PROTOCOL_UDP "udp"
#define PROTOCOL_TCP "tcp"
typedef set<pair<unsigned int, unsigned int> > IPTABLE;

class Firewall
{
public:
	Firewall();
	Firewall(string filename);
	~Firewall();
	bool accept_packet (string direction, string protocol, int port, string ip_address);
private:
	map<int, IPTABLE > inb_tcp_iptables;
	map<int, IPTABLE > inb_udp_iptables;
	map<int, IPTABLE > outb_tcp_iptables;
	map<int, IPTABLE > outb_udp_iptables;
	void add_rule(string &rule);
	unsigned int ip_to_unsigned_int(string &ip);
};


#endif /* SRC_FIREWALL_H_ */
