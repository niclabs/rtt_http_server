The server runs a sniffer and an http server.

The sniffers  sniff the info on the port that the current server is running. It gets the rtt on the tcp handshake (time between the arrival of the fist SYN and the ACK rigth after the SYN-ACK).

The server responds the http request with the rtt the sniffer calculates.

## To run server and (sniffer)
```
sudo python server_sniffer.py <host_ip> <host_port>
```

## To run example client

```
python rtt_tcp_client.py <host_ip> <host_port>
```