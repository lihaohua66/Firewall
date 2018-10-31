/*
 * firwall.cpp
 *
 *      Author: lihaohua
 */


#include "firewall.h"

Firewall::Firewall()
{

}

Firewall::Firewall(string filename)
{
	ifstream fs(filename.c_str(), ios::in );
	if(!fs){
		return;
	}
	string rule;
	while(getline(fs, rule))
	{
		add_rule(rule);
	}
}

Firewall::~Firewall()
{
	this->inb_tcp_iptables.clear();
	this->inb_udp_iptables.clear();
	this->outb_tcp_iptables.clear();
	this->outb_udp_iptables.clear();
}

bool Firewall::accept_packet (string direction, string protocol, int port, string ip_address)
{
	map<int, IPTABLE> *m = nullptr;
	if(direction==DIRECTION_INBOUND){
		if(protocol == PROTOCOL_TCP){
			m = &this->inb_tcp_iptables;
		}else if(protocol == PROTOCOL_UDP){
			m = &this->inb_udp_iptables;
		}
	}else if(direction==DIRECTION_OUTBOUND){
		if(protocol == PROTOCOL_TCP){
			m = &this->outb_tcp_iptables;
		}else if(protocol == PROTOCOL_UDP){
			m = &this->outb_udp_iptables;
		}
	}
	unsigned int ip_num = ip_to_unsigned_int(ip_address);
	if((*m).find(port)!=(*m).end()){
		IPTABLE::iterator it = (*m)[port].upper_bound(make_pair(ip_num, ip_num));
		if(it == (*m)[port].begin())
			return false;
		it--;
		if(ip_num>=it->first && ip_num<=it->second){
			return true;
		}
	}
	return false;
}
void Firewall::add_rule(string &rule){
	stringstream ss(rule);
	string direction, protocol, port, ip;
	getline(ss, direction, ',');
	getline(ss, protocol, ',');
	getline(ss, port, ',');
	getline(ss, ip, ',');
	map<int, IPTABLE> *m;
	if(direction==DIRECTION_INBOUND){
		if(protocol == PROTOCOL_TCP){
			m = &this->inb_tcp_iptables;
		}else if(protocol == PROTOCOL_UDP){
			m = &this->inb_udp_iptables;
		}
	}else if(direction==DIRECTION_OUTBOUND){
		if(protocol == PROTOCOL_TCP){
			m = &this->outb_tcp_iptables;
		}else if(protocol == PROTOCOL_UDP){
			m = &this->outb_udp_iptables;
		}
	}
	int port_left, port_right;
	unsigned int ip_left, ip_right;
	size_t pos = port.find('-');
	if(pos==string::npos){
		port_left = port_right = stoi(port);
	}else{
		port_left = stoi(port.substr(0, pos));
		port_right = stoi(port.substr(pos+1));
	}
	pos = ip.find('-');
	if(pos==string::npos){
		ip_left = ip_right = ip_to_unsigned_int(ip);
	}else{
		string left = ip.substr(0, pos);
		ip_left = ip_to_unsigned_int(left);
		string right = ip.substr(pos+1);
		ip_right = ip_to_unsigned_int(right);
	}
	for(int i=port_left; i<=port_right; i++){
		IPTABLE::iterator it;
		it = (*m)[i].lower_bound(make_pair(ip_left, ip_right));
		while(it!=(*m)[i].end() && it->first <= ip_right){
			if(it->second > ip_right){
				ip_right = it->second;
			}
			(*m)[i].erase(*it);
			it = (*m)[i].lower_bound(make_pair(ip_left, ip_right));
		}
		(*m)[i].insert(make_pair(ip_left, ip_right));
	}
}

unsigned int Firewall::ip_to_unsigned_int(string &ip){
	unsigned int res = 0;
	stringstream ss(ip);
	string s;
	while( getline(ss, s, '.')){
		res = res * 256 + stoi(s);
	}
	return res;
}
