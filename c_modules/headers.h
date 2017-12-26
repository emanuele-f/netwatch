#define ARP_REQUEST 0x1
#define ARP_REPLY 0x2
#define PROTOCOL_TYPE_IP 0x0800
#define HARDWARE_TYPE_ETHERNET 0x1
#define ETH_ALEN 6

#define ETH_P_IP	0x0800      /* Internet Protocol packet	*/
#define ETH_P_ARP	0x0806      /* Address Resolution packet	*/
#define IP_PROTO_UDP 17

struct ethhdr {
  u_char h_dest[ETH_ALEN];    /* destination eth addr */
  u_char h_source[ETH_ALEN];  /* source ether addr */
  u_int16_t	h_proto;          /* packet type ID field */
} __attribute__((packed));

struct arphdr { 
  u_int16_t htype;    /* Hardware Type           */ 
  u_int16_t ptype;    /* Protocol Type           */ 
  u_char hlen;        /* Hardware Address Length */ 
  u_char plen;        /* Protocol Address Length */ 
  u_int16_t oper;     /* Operation Code          */ 
  u_char sha[6];      /* Sender hardware address */ 
  u_char spa[4];      /* Sender IP address       */ 
  u_char tha[6];      /* Target hardware address */ 
  u_char tpa[4];      /* Target IP address       */ 
} __attribute__((packed));

struct udphdr {
  u_int16_t sport;
  u_int16_t dport;
  u_int16_t len;
  u_int16_t checksum;
};

struct dhcp_boot_request {
  u_int8_t request_type;
  const u_char *host_name_ptr;
  const u_char *cli_id_ptr;
  u_int32_t server_identifier;
  u_int32_t requested_ip;
  u_int host_name_len;
};

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128
#define DHCP_VEND_LEN 308
#define DHCP_OPTION_MAGIC_NUMBER  0x63825363
#define DHCP_MSGTYPE_BOOT_REQUEST 0x1
#define DHCP_MSGTYPE_BOOT_REPLY 0x2
#define DHCP_MSGTYPE_MESSAGE_ACK 0x2
#define DHCP_OPTION_MESSAGE_TYPE 0x35
#define DHCP_OPTION_MESSAGE_TYPE_DISCOVER 0x1
#define DHCP_OPTION_MESSAGE_TYPE_ACK 0x5
#define DHCP_OPTION_MESSAGE_TYPE_NACK 0x6
#define DHCP_OPTION_MESSAGE_TYPE_OFFER 0x2
#define DHCP_OPTION_MESSAGE_TYPE_REQUEST 0x3
#define DHCP_OPTION_HOST_NAME 0x0c
#define DHCP_OPTION_CLIENT_ID 0x3d
#define DHCP_OPTION_DHCP_SERVER_IDENTIFIER 0x36
#define DHCP_OPTION_LEASE_TIME 0x33
#define DHCP_OPTION_RENEWAL_TIME 0x3a
#define DHCP_OPTION_REBINDING_TIME 0x3b
#define DHCP_OPTION_SUBNET_MASK 0x01
#define DHCP_OPTION_BROADCAST_ADDRESS 0x1c
#define DHCP_OPTION_DNS_SERVER 0x06
#define DHCP_OPTION_ROUTER 0x03
#define DHCP_OPTION_REQUESTED_IP 0x32
#define DHCP_OPTION_HARDWARE_TYPE_ETHERNET 0x01
#define DHCP_OPTION_END 0xFF

struct dhcp_packet_t {
  uint8_t msgType;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;/* 4 */
  uint16_t secs;/* 8 */
  uint16_t flags;
  uint32_t ciaddr;/* 12 */
  uint32_t yiaddr;/* 16 */
  uint32_t siaddr;/* 20 */
  uint32_t giaddr;/* 24 */
  uint8_t chaddr[DHCP_CHADDR_LEN]; /* 28 */
  uint8_t sname[DHCP_SNAME_LEN]; /* 44 */
  uint8_t file[DHCP_FILE_LEN]; /* 108 */
  uint32_t magic; /* 236 */
  uint8_t options[DHCP_VEND_LEN];
} __attribute__((packed));