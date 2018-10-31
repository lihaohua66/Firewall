# How to use
1. To test with my test case, go to the folder `/src` and run command `make all`. Then simply run command `./test1` to check the correctness of the solution, or run command `./test1M` to check the performance (may take longer as to load 1M rules). <br>
2. To test with the source code, you may include header file `"firewall.h"` in your code.<br>
Then initialize the object and test as follow:<br>
>>>> `Firewall fw = Firewall([your file path]);`<br>
>>>> `fw.accept_packet(direction, protocol, port, ip_address);`<br>


# Design an implementation
## 1. How to test solution <br>
### (a) Correctness<br>
I design several test case, which covers lots of cases. For example, a rule could be consists of single/range port, single range ip address.<br>
### (b) Performance<br>
I randomly generate a test case with 1M rules. Then I randomly generate 10000 test queries and estimate the performance after all rules are loaded.<br>
   
## 2. Design<br>
To speed up the search, I group the IP address and port for all the combination of direction and protocol. In our case, I use for map to store the IP addree and port, which is named as `inb_tcp_iptables`, `inb_udp_iptables`, `outb_tcp_iptables`,  `outb_udp_iptables`.<br>
For each map, the key is port number and the value is a set of all IP address which fulfills these criteria. Saying there is a ip address 192.168.1.1 in the set with key 80 in `inb_tcp_iptables`, it means we have a rule as inbound,tcp,80,192.168.1.1.<br>
If we have a rule with range port, we will store the ip address for each port. Although it may take more space, it could help us to speed up the search. As IP address in the same set share the sam criteria, we could merge the ip address if there is a overlap. Then we could use binary search to quickly find if a specific IP address exists in the set. <br>

## 3. More to implement
As my current solution makes some trade off between space complexity and time complexity, the memory cost is a little bit higher. However we could store all the data to the file system. Then when we do the search, we could quickly find the file which may contains the rule. 

## 4. Time complexity and space complexity
The time complexity will be O(log(n)) as we use map and set. Each time we get a new query, we first determine the map by direction and protocol, it is O(1). Then we check the if any ip address in the set of given port. Then we use binary search to quickly check if the given IP address exists in this set, it is O(log(n)).<br>
The space complexity will be O(4 * 65536 * n) in the worst case. 

# Interested team
I am intereste in Data Team and Platform Team, and the ranking would be Data Team > Platform Team.
