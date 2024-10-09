# egress tcp drop

Drop egress TCP packets based on <desitnation IP, port number> pair

## How to use

- Clone the repositoty and change directory inside the project
```bash
$ git clone https://github.com/MeherRushi/egress_tcp_drop_gadget.git
$ cd egress_tcp_drop_gadget/
```

- Build the image after setting the experimental tag
```bash
$ export IG_EXPERIMENTAL=true
$ sudo -E ig image build -t tcp_pkt_dropper .
```

- Run the image
```bash
$ sudo -E ig run ghcr.io/inspektor-gadget/gadget/tcp_pkt_dropper:latest --public-keys=""
```

## Working

This program drops all the TCP packets at the tc hookpoint, given the IPv4 address. If not mentioned, all the packets will be dropped.

We also track the number of the packets dropped per <desitnation IP, port number> pair

## Approach

I actually faced a little bit of an issue trying to take the IP address as a string/array or in the natural format (such as 127.0.0.1 or 2001:db8:: ), but I kept on running into marshalling errors of the parameters.

So temporarily I thought of taking IPv4 address and port using flags --a,--b,--c,--d,--p as described in the [flag section](#flags).

## Future Work

- improve the input flags format

- extend the input to IPv6 as well

- Can look into the filtering based on container mount id as well

- /* 
# user space
- Change the IP parameter for ipv4 and ipv6 - need to read code
- then use kubeIPresolver to filter by name etc 
	- looks like for the non image based gadgets
 */



## Flags

#### `--a`
- **Description:** The first 8 bits of the filter IPv4 address in Integer Format (e.g., 127)
- **Default value:** `0`

#### `--b`
- **Description:** The second 8 bits of the filter IPv4 address in Integer Format (e.g., 0)
- **Default value:** `0`

#### `--c`
- **Description:** The third 8 bits of the filter IPv4 address in Integer Format (e.g., 0)
- **Default value:** `0`

#### `--d`
- **Description:** The last 8 bits of the filter IPv4 address in Integer Format (e.g., 1)
- **Default value:** `0`

#### `--p`
- **Description:** Port number (e.g., 443)
- **Default value:** `0`

#### `--iface`
- **Description:** Network interface to attach to
- **Default value:** `""`


### Example Command :
```bash
sudo -E irun ghcr.io/inspektor-gadget/gadget/tcp_pkt_dropper:latest --public-keys="" --a 110 --b 77 --c 250 --d 142 --p 443
```

- This will filter and drop the TCP packets with destination address, port pair `110.77.142:443`


## Screenshot

![refrence_image](public/demo.png)

## Requirements

- ig v0.26.0 (CHANGEME)
- Linux v5.15 (CHANGEME)

## License (CHANGEME)

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
