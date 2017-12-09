# Wireghost
Wireghost is a Linux Kernel Module (tested on kernel 4.4) that mangles TCP connections without either end of the TCP connection recognizing a change.  This allows a man-in-the middle attack that can now instead of just snooping information, can actually modify what is being sent through the connection.  

The two ways Wireghost mangles TCP connections is via mangling and injecting.  Given a string and a replacement for that string, Wireghost can intercept a packet that matches the string, replace it with your given replacement, and let the packet continue down the connection.  The TCP connection is never broken in this process either.

The second way Wireghost can modify a connectin is by injecting a packet.  At any given trigger, Wireghost will inject a packet of your desired contents into the connection, and neither computer will reject the packet and the TCP connection is still maintained. 
