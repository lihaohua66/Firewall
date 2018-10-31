/*
 * test1M.cpp
 *
 *      Author: lihaohua
 */

#include "firewall.h"
#include <time.h>

int main(){
	string filename = "../data/data1M.csv";
	Firewall fw = Firewall(filename);
	clock_t startTime, endTime;
	startTime = clock();
	for(int i=0; i<10000; i++){
		string direction = "inbound";
		string protocol = "tcp";
		int port = rand()%65535+1;
		string ip = to_string(rand()%256) + "."
				+   to_string(rand()%256) + "."
				+   to_string(rand()%256) + "."
				+	to_string(rand()%256);
		fw.accept_packet(direction, protocol, port, ip);
	}
	endTime = clock();
	cout<<"Total time for 10000 query with 1M data: "<< double((endTime-startTime))/CLOCKS_PER_SEC*1000 <<"ms" << endl;
	return 0;
}


