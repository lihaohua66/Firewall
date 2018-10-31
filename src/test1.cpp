/*
 * test1.cpp
 *
 *      Author: lihaohua
 */
#include "firewall.h"

int main(){
	string filename = "../data/test1.csv";
	Firewall fw = Firewall(filename);
	bool accept;
	
	//single rule match
	accept =	 fw.accept_packet("inbound","udp", 53, "192.168.2.1");
	assert(accept == true && "Rule 3 match");
	
	//single rule not match
	accept = fw.accept_packet("inbound","tcp", 81, "192.168.1.2");
        assert(accept == false && "No match");
	
	//rule with range port match
	accept = fw.accept_packet("outbound","tcp", 10234, "192.168.10.11");
	assert(accept == true && "Rule 2 match");
	
	//rule with range port not match
	accept = fw.accept_packet("outbound","tcp", 20234, "192.168.10.11");
	assert(accept == false && "No match");
	
	//rule with range port range ip not match
	accept = fw.accept_packet("inbound","udp", 53, "192.169.2.1");
	assert(accept == false && "No match");

	//rule with range port range ip match
	accept = fw.accept_packet("inbound","udp", 53, "192.154.1.1");
	assert(accept == true && "Rule 5 match");

	accept = fw.accept_packet("inbound","udp", 71, "192.169.2.1");
	assert(accept == true && "Rule 6 match");

	return 0;
}

