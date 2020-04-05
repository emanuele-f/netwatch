/*
 * netwatch
 * (C) 2017-20 Emanuele Faranda
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "headers.h"

#define SNAPLEN 1024
#define PROMISC 1

#define min(x, y) ((x) <= (y) ? (x) : (y))

//#define DEBUG
//#define USE_SAMPLE_PCAP

typedef struct {
  char mac_buf[18];
  char ip_buf[INET_ADDRSTRLEN];
  char name_buf[64];
  char dns_buf[128];
  char proto[32];
} PacketInfo;

typedef struct {
  PyObject_HEAD

  pcap_t *handle;
  u_char iface_mac[6];
  u_char gateway_mac[6];
  uint32_t iface_ip;
  uint32_t gateway_ip;
} pkt_readerObject;

/* ************************************************************ */

static char* format_mac(u_char *mac, char *buf, int buf_len) {
  snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0] & 0xFF, mac[1] & 0xFF,
    mac[2] & 0xFF, mac[3] & 0xFF,
    mac[4] & 0xFF, mac[5] & 0xFF);
  return(buf);
}

static int parse_mac(const char *m, u_char *parsed) {
  return(sscanf(m, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
    &parsed[0], &parsed[1], &parsed[2],
    &parsed[3], &parsed[4], &parsed[5]) == 6);
}

/* ************************************************************ */

static pcap_t* _open_capture_dev(const char *devname, int read_timeout, const char *filter_exp, int immediate_mode) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  pcap_t *handle = NULL;
  
  // Note for packet timeout: heavy buffering makes timouts impredictable
  // https://github.com/the-tcpdump-group/libpcap/issues/572

  if(immediate_mode) {
    pcap_t *_handle;
    _handle = pcap_create(devname, errbuf);

    if (_handle)
      if (pcap_set_timeout(_handle, read_timeout) == 0)
        if (pcap_set_snaplen(_handle, SNAPLEN) == 0)
          if (pcap_set_promisc(_handle, PROMISC) == 0)
            if (pcap_set_immediate_mode(_handle, 1) == 0)
              if (pcap_activate(_handle) == 0)
                handle = _handle;
 } else {
#if ! defined USE_SAMPLE_PCAP
  handle = pcap_open_live(devname, SNAPLEN, PROMISC, read_timeout, errbuf);
#else
  handle = pcap_open_offline("dhcp.pcap", errbuf);
#endif
  }

  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", devname, errbuf);
    return NULL;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", devname);
    pcap_close(handle);
    return NULL;
  }

  if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    pcap_freecode(&fp);
    pcap_close(handle);
    return NULL;
  }

  pcap_freecode(&fp);

  return handle;
}

/* ************************************************************ */

static void _close_capture_dev(pcap_t *handle) {
  pcap_close(handle);
}

/* ************************************************************ */

/*
 * Read a packet from wire and extract relevant information.
 *
 * If relevant information is found, 1 is returned. Otherwise 0 is returned.
 *
 * When 1 is retuned, the mac_buf and ip_buf parameters will be filled accordingly.
 * When 1 is retuned, the name_buf will only be set if a relevant name as been found.
 */
static int _read_packet_info(pcap_t *handle, PacketInfo *pinfo) {
  struct pcap_pkthdr header;
  struct in_addr ip_addr;
  struct arphdr *arp;
  struct ip *ip_header;
  struct ethhdr *eth_header;
  struct udphdr *udp_header;
  int iphdr_len;
  const u_char *packet = pcap_next(handle, &header);
  int len = header.len;

  if (! packet) return 0;

  if (len >= sizeof(struct ethhdr)) {
    eth_header = (struct ethhdr *) packet;
    len -= sizeof(struct ethhdr);

    if ((ntohs(eth_header->h_proto) == ETH_P_ARP) && (len >= sizeof(struct arphdr))) {
      arp = (struct arphdr *)(packet + sizeof(struct ethhdr));
      len -= sizeof(struct arphdr);

      if ((ntohs(arp->htype) == HARDWARE_TYPE_ETHERNET)
              && (ntohs(arp->ptype) == PROTOCOL_TYPE_IP)) {
        if ((ntohs(arp->oper) == ARP_REQUEST) || (ntohs(arp->oper) == ARP_REPLY)) {
          ip_addr.s_addr = *((u_int32_t*) arp->spa);
          inet_ntop(AF_INET, &ip_addr, pinfo->ip_buf, sizeof(pinfo->ip_buf));
          format_mac(arp->sha, pinfo->mac_buf, sizeof(pinfo->mac_buf));

          strcpy(pinfo->proto, ((ntohs(arp->oper) == ARP_REQUEST) ? "ARP_REQ" : "ARP_REP"));

#ifdef DEBUG
          printf("Got an %d bytes ARP packet\n", header.len);
          printf("From %s (%s) %s\n", pinfo->ip_buf, pinfo->mac_buf, pinfo->proto);
#endif

          return 1;
        }
      }
    } else if ((ntohs(eth_header->h_proto) == ETH_P_IP) && (len >= sizeof(struct ip))) {
      ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
      iphdr_len = ip_header->ip_hl * 4;

      if (len >= iphdr_len) {
        len -= iphdr_len;

        if(ip_header->ip_v == IPVERSION) {
          inet_ntop(AF_INET, &ip_header->ip_src, pinfo->ip_buf, sizeof(pinfo->ip_buf));
          format_mac(eth_header->h_source, pinfo->mac_buf, sizeof(pinfo->mac_buf));

#ifdef DEBUG
          printf("Got a %d bytes IPv4 [iphdr_len=%d] packet\n", header.len, iphdr_len);
          printf("From %s (%s)\n", pinfo->ip_buf, pinfo->mac_buf);
#endif

          if ((ip_header->ip_p == IP_PROTO_UDP) && (len >= sizeof(struct udphdr))) {
            udp_header = (struct udphdr *)((u_char *)ip_header + iphdr_len);
            // udp header len is udp header + data
            //len -= sizeof(struct udphdr);

#ifdef DEBUG
            printf("UDP: %d -> %d [%d len][%d udp len]\n", ntohs(udp_header->sport), ntohs(udp_header->dport), len, ntohs(udp_header->len));
#endif

            if ((ntohs(udp_header->sport) == 68) && (ntohs(udp_header->dport) == 67) &&
                    (len >= ntohs(udp_header->len)) && (ntohs(udp_header->len) >= sizeof(struct dhcp_packet_t))) {
              struct dhcp_packet_t *dhcp = (struct dhcp_packet_t *) ((u_char *)udp_header + sizeof(struct udphdr));

              if((dhcp->magic == htonl(DHCP_OPTION_MAGIC_NUMBER))
                    && (dhcp->hlen == 6)
                    && (dhcp->msgType == DHCP_MSGTYPE_BOOT_REQUEST)) {
                struct dhcp_boot_request request = {0};
                int i = 0;

                while(i < len) {
                  u_int8_t opt = dhcp->options[i];
                  u_int8_t optlen = dhcp->options[i+1];
                  const u_char *optval = &dhcp->options[i+2];

                  if (opt == DHCP_OPTION_MESSAGE_TYPE) {
                    request.request_type = *optval;
                  } else if (opt == DHCP_OPTION_HOST_NAME) {
                    request.host_name_ptr = optval;
                    request.host_name_len = optlen;
                  } else if ((opt == DHCP_OPTION_CLIENT_ID)
                   && (optlen == 7)
                   && (*optval == DHCP_OPTION_HARDWARE_TYPE_ETHERNET)) {
                    request.cli_id_ptr = &optval[1];
                  } else if ((opt == DHCP_OPTION_DHCP_SERVER_IDENTIFIER) && (optlen == 4)) {
                    request.server_identifier = ntohl(*((u_int32_t *)optval));
                  } else if ((opt == DHCP_OPTION_REQUESTED_IP) && (optlen == 4)) {
                    request.requested_ip = ntohl(*((u_int32_t *)optval));;
                  } else if (opt == DHCP_OPTION_END)
                    break;

                  i += optlen + 2;
                }

                if ((request.request_type == DHCP_OPTION_MESSAGE_TYPE_REQUEST) && (request.requested_ip != 0)) {
                  ip_addr.s_addr = htonl(request.requested_ip);
                  inet_ntop(AF_INET, &ip_addr, pinfo->ip_buf, sizeof(pinfo->ip_buf));

                  if(request.host_name_ptr != NULL) {
                    strncpy(pinfo->name_buf, (char*)request.host_name_ptr, min(sizeof(pinfo->name_buf)-1, request.host_name_len));
                    pinfo->name_buf[min(sizeof(pinfo->name_buf)-1, request.host_name_len)] = '\0';
                  }

                  strcpy(pinfo->proto, "DHCP_REQ");

#ifdef DEBUG
                  printf("DHCP REQUEST: %s %s\n", pinfo->ip_buf, request.host_name_ptr ? pinfo->name_buf : "");
#endif
                } else
                  return 0;
              } else
               return 0;
            } else if ((ntohs(udp_header->dport) == 53) && (len >= ntohs(udp_header->len)) && (ntohs(udp_header->len) >= sizeof(struct dns_packet_t))) {
              struct dns_packet_t* dns = (struct dns_packet_t *) ((u_char *)udp_header + sizeof(struct udphdr));
              len -= sizeof(struct udphdr);

              if(((ntohs(dns->flags) & DNS_FLAGS_MASK) == DNS_TYPE_REQUEST) && ntohs(dns->questions >= 1)) {
                int i;

                for(i=0; i<min(sizeof(pinfo->dns_buf)-1, len); i++) {
                  char c = dns->queries[i];

                  if(!c)
                    break;
                  else if(c < ' ')
                    c = '.';

                  pinfo->dns_buf[i] = c;
                }

                pinfo->dns_buf[i] = '\0';

                strcpy(pinfo->proto, "DNS_REQ");

                //printf("DNS REQUEST: %s %s\n", ip_buf, pinfo->dns_buf);
              }
            }
          }

          return 1;
        }
      }
    }
  }

  return 0;
}

/* ************************************************************ */

static int _send_spoofed_arp(pkt_readerObject *reader,
        u_int32_t target_ip, u_char *target_mac, int op_type, int poison) {
  struct arppkt arp;
  u_char *source_mac = poison ? reader->iface_mac : reader->gateway_mac;

  /* Ethernet */
  arp.proto = htons(0x0806);
  memcpy(arp.dst_mac, target_mac, sizeof(arp.dst_mac));
  memcpy(arp.src_mac, source_mac, sizeof(arp.src_mac));

  /* ARP */
  arp.arph.htype = htons(1);
  arp.arph.ptype = htons(0x0800);
  arp.arph.hlen = 6;
  arp.arph.plen = 4;
  arp.arph.oper = htons(op_type);
  *((u_int32_t *)&arp.arph.spa) = reader->gateway_ip;
  *((u_int32_t *)&arp.arph.tpa) = target_ip;
  memcpy(arp.arph.tha, target_mac, sizeof(arp.dst_mac));
  memcpy(arp.arph.sha, source_mac, sizeof(arp.src_mac));

  return pcap_sendpacket(reader->handle, (u_char*)&arp, sizeof(arp));
}

/* ************************************************************ */

static PyTypeObject pkt_readerType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "pkt_reader",              /* tp_name */
  sizeof(pkt_readerObject),  /* tp_basicsize */
  0,                         /* tp_itemsize */
  0,                         /* tp_dealloc */
  0,                         /* tp_print */
  0,                         /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_compare */
  0,                         /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
  0,                         /* tp_hash */
  0,                         /* tp_call */
  0,                         /* tp_str */
  0,                         /* tp_getattro */
  0,                         /* tp_setattro */
  0,                         /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,        /* tp_flags */
  "A reader on the pcap handle",           /* tp_doc */
};

/* ************************************************************ */

static int get_gateway_info(uint32_t *gateway_ip, u_char *gateway_mac) {
  FILE *fd;
  char *token = NULL;
  char *gateway_ip_str = NULL;
  char buf[256];
  u_int8_t mac_ok = 0;

  if(!(fd = fopen("/proc/net/route", "r")))
    return(-1);

  // Gateway IP
  while(fgets(buf, sizeof(buf), fd)) {
    if(strtok(buf, "\t") && (token = strtok(NULL, "\t")) && (!strcmp(token, "00000000"))) {
      token = strtok(NULL, "\t");

      if(token) {
        struct in_addr addr;

        addr.s_addr = strtoul(token, NULL, 16);
        gateway_ip_str = inet_ntoa(addr);

        if(gateway_ip_str) {
          *gateway_ip = addr.s_addr;
          break;
        }
      }
    }
  }

  fclose(fd);

  if(!gateway_ip_str)
    return(-2);

  if(!(fd = fopen("/proc/net/arp", "r")))
    return(-3);

  // Gateway MAC address
  while(fgets(buf, sizeof(buf), fd)) {
    if((token = strtok(buf, " ")) && !strcmp(token, gateway_ip_str)) {
      if(strtok(NULL, " ") && strtok(NULL, " ") && (token = strtok(NULL, " "))) {
        mac_ok = parse_mac(token, gateway_mac);
        break;
      }
    }
  }

  fclose(fd);

  if(!mac_ok)
    return(-4);

  return(0);
}

/* ************************************************************ */

static int get_interface_ip_address(const char *iface, uint32_t *ip) {
  struct ifreq ifr;
  int fd;
  int rv;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char *)ifr.ifr_name, iface, IFNAMSIZ-1);

  if((rv = ioctl(fd, SIOCGIFADDR, &ifr)) != -1)
    *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

  close(fd);
  return(rv);
}

/* ************************************************************ */

static int get_interface_mac_address(const char *iface, u_char *mac) {
  struct ifreq ifr;
  int fd;
  int rv;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char *)ifr.ifr_name, iface, IFNAMSIZ-1);

  if((rv = ioctl(fd, SIOCGIFHWADDR, &ifr)) != -1)
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 8);

  close(fd);
  return(rv);
}

/* ************************************************************ */

static PyObject *open_capture_dev(PyObject *self, PyObject *args) {
  const char *devname, *filter_exp;
  int read_timeout;
  int immediate_mode;
  int rv;
  pcap_t *handle;

  if (!PyArg_ParseTuple(args, "sisb", &devname, &read_timeout, &filter_exp, &immediate_mode))
    return NULL;

  handle = _open_capture_dev(devname, read_timeout, filter_exp, immediate_mode);

  if (!handle)
    return NULL;

  pkt_readerObject* reader;
  reader = (pkt_readerObject*) pkt_readerType.tp_new(&pkt_readerType, NULL, NULL);
  reader->handle = handle;

  // Interface IP
  if((rv = get_interface_ip_address(devname, &reader->iface_ip)) == -1) {
    fprintf(stderr, "Could not get interface %s IP address [%d]\n", devname, rv);
    return NULL;
  }

  // Interface MAC
  if((rv = get_interface_mac_address(devname, reader->iface_mac)) == -1) {
    fprintf(stderr, "Could not get interface %s MAC address [%d]\n", devname, rv);
    return NULL;
  }

  // Gateway information
  if((rv = get_gateway_info(&reader->gateway_ip, reader->gateway_mac)) != 0) {
    fprintf(stderr, "Could not get gateway information [%d]\n", rv);
    return NULL;
  }

  if (! reader)
    return NULL;

  return (PyObject *)reader;
}

/* ************************************************************ */

static PyObject *close_capture_dev(PyObject *self, PyObject *args) {
  pkt_readerObject *reader;

  if (!PyArg_ParseTuple(args, "O", &reader))
    return NULL;

  _close_capture_dev(reader->handle);

  Py_DECREF(reader);

  return Py_BuildValue("s", NULL);
}

/* ************************************************************ */

static PyObject *read_packet_info(PyObject *self, PyObject *args) {
  PyObject *dict;
  pkt_readerObject *reader;
  PacketInfo pinfo;

  if (!PyArg_ParseTuple(args, "O", &reader))
    return NULL;

  memset(&pinfo, 0, sizeof(pinfo));

  if (! _read_packet_info(reader->handle, &pinfo))
    return Py_BuildValue("s", NULL);

  dict = PyDict_New();
  if (! dict)
    return NULL;

  if (pinfo.mac_buf[0]) PyDict_SetItemString(dict, "mac", PyUnicode_FromString(pinfo.mac_buf));
  if (pinfo.ip_buf[0]) PyDict_SetItemString(dict, "ip", PyUnicode_FromString(pinfo.ip_buf));
  if (pinfo.name_buf[0]) PyDict_SetItemString(dict, "name", PyUnicode_FromString(pinfo.name_buf));
  if (pinfo.dns_buf[0]) PyDict_SetItemString(dict, "query", PyUnicode_FromString(pinfo.dns_buf));
  if (pinfo.proto[0]) PyDict_SetItemString(dict, "proto", PyUnicode_FromString(pinfo.proto));

  return dict;
}

/* ************************************************************ */

static PyObject *arp_spoof(PyObject *self, PyObject *args, int arp_op, int poison) {
  pkt_readerObject *reader;
  const char *target_mac_str, *target_ip_str;
  uint32_t target_ip;
  u_char target_mac[6];

  if (!PyArg_ParseTuple(args, "Oss", &reader, &target_mac_str, &target_ip_str))
    return NULL;

  target_ip = inet_addr(target_ip_str);

  if(target_ip == INADDR_NONE)
    return NULL;

  if(!parse_mac(target_mac_str, target_mac))
    return NULL;

//~ #ifdef DEBUG
  printf("%s %s (%s) [%s]\n", poison ? "Spoofing" : "Rearping",
    target_mac_str, target_ip_str, (arp_op == ARP_REQUEST) ? "ARP_REQ" : "ARP_REP");
//~ #endif

  if(_send_spoofed_arp(reader, target_ip, target_mac, arp_op, poison) == 0)
    Py_RETURN_TRUE;

  Py_RETURN_FALSE;
}

static inline PyObject *arp_req_spoof(PyObject *self, PyObject *args) { return(arp_spoof(self, args, ARP_REQUEST, 1)); }
static inline PyObject *arp_rep_spoof(PyObject *self, PyObject *args) { return(arp_spoof(self, args, ARP_REPLY, 1)); }
static inline PyObject *arp_rearp(PyObject *self, PyObject *args)     { return(arp_spoof(self, args, ARP_REQUEST, 0)); }

/* ************************************************************ */

static PyObject *get_iface_ip(PyObject *self, PyObject *args) {
  pkt_readerObject *reader;
  struct in_addr addr;

  if(!PyArg_ParseTuple(args, "O", &reader))
    return NULL;

  addr.s_addr = reader->iface_ip;

  return PyUnicode_FromString(inet_ntoa(addr));
}

/* ************************************************************ */

static PyObject *get_iface_mac(PyObject *self, PyObject *args) {
  pkt_readerObject *reader;
  char mac[18];

  if(!PyArg_ParseTuple(args, "O", &reader))
    return NULL;

  format_mac(reader->iface_mac, mac, sizeof(mac));

  return PyUnicode_FromString(mac);
}

/* ************************************************************ */

static PyObject *get_gateway_mac(PyObject *self, PyObject *args) {
  pkt_readerObject *reader;
  char mac[18];

  if(!PyArg_ParseTuple(args, "O", &reader))
    return NULL;

  format_mac(reader->gateway_mac, mac, sizeof(mac));

  return PyUnicode_FromString(mac);
}

/* ************************************************************ */

static PyObject *get_gateway_ip(PyObject *self, PyObject *args) {
  pkt_readerObject *reader;
  struct in_addr addr;

  if(!PyArg_ParseTuple(args, "O", &reader))
    return NULL;

  addr.s_addr = reader->gateway_ip;

  return PyUnicode_FromString(inet_ntoa(addr));
}

/* ************************************************************ */

static PyMethodDef PktReaderMethods[] = {
  {"open_capture_dev",  open_capture_dev, METH_VARARGS, "Open a device for capture."},
  {"close_capture_dev", close_capture_dev, METH_VARARGS, "Closes a devices capture."},
  {"read_packet_info", read_packet_info, METH_VARARGS, "Read packet information. None is returned if no packet information is available."},
  {"arp_req_spoof", arp_req_spoof, METH_VARARGS, "Send a spoofed ARP request"},
  {"arp_rep_spoof", arp_rep_spoof, METH_VARARGS, "Send a spoofed ARP reply"},
  {"arp_rearp", arp_rearp, METH_VARARGS, "Re-arp the device to the original gateway"},
  {"get_iface_ip", get_iface_ip, METH_VARARGS, "Get the interface IP address"},
  {"get_iface_mac", get_iface_mac, METH_VARARGS, "Get the interface MAC address"},
  {"get_gateway_mac", get_gateway_mac, METH_VARARGS, "Get the gateway MAC address"},
  {"get_gateway_ip", get_gateway_ip, METH_VARARGS, "Get the gateway IP address"},
  {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyMODINIT_FUNC PyInit_pkt_reader() {
  if (PyType_Ready(&pkt_readerType) < 0)
    return(NULL);

  pkt_readerType.tp_new = PyType_GenericNew;

  static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "pkt_reader", NULL /* doc */, -1, PktReaderMethods,
  };

  return(PyModule_Create(&moduledef));
}

/* ************************************************************ */

//#define PKT_READER_AUTOTEST
#ifdef PKT_READER_AUTOTEST

int main(int argc, char *argv[]) {
  const char *devname = "wlan0";
  PacketInfo pinfo;

  pcap_t *dev = _open_capture_dev(devname, 1000, "broadcast or arp", 0);

  if (dev != NULL) {
    printf("Capturing packets on %s...\n", devname);

    while(1) {
      memset(&pinfo, 0, sizeof(pinfo));

      if (_read_packet_info(dev, &pinfo)) {
        printf("+ Seen %s as %s [name=%s][dns=%s]\n", pinfo->mac_buf, pinfo->ip_buf, pinfo->name_buf, pinfo->dns_buf);
      }
    }

    _close_capture_dev(dev);
  }

  return(0);
}

#endif
