/*
 * netwatch
 * (C) 2017-18 Emanuele Faranda
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

#include "headers.h"

#define SNAPLEN 1024
#define PROMISC 1
#define MAC_BUF_SIZE 18
#define IP_BUF_SIZE INET_ADDRSTRLEN
#define NAME_BUF_SIZE 64
#define DNS_QUERY_SIZE 128

#define min(x, y) ((x) <= (y) ? (x) : (y))

//#define DEBUG
//#define USE_SAMPLE_PCAP

/* ************************************************************ */

static char* format_mac(u_char *mac, char *buf, int buf_len) {
  snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0] & 0xFF, mac[1] & 0xFF,
    mac[2] & 0xFF, mac[3] & 0xFF,
    mac[4] & 0xFF, mac[5] & 0xFF);
  return(buf);
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
static int _read_packet_info(pcap_t *handle, char *mac_buf, char *ip_buf, char *name_buf, char *dns_query) {
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
          inet_ntop(AF_INET, &ip_addr, ip_buf, IP_BUF_SIZE);
          format_mac(arp->sha, mac_buf, MAC_BUF_SIZE);

#ifdef DEBUG
          printf("Got an %d bytes ARP packet\n", header.len);
          printf("From %s (%s) %s\n", ip_buf, mac_buf, (ntohs(arp->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");
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
          inet_ntop(AF_INET, &ip_header->ip_src, ip_buf, IP_BUF_SIZE);
          format_mac(eth_header->h_source, mac_buf, MAC_BUF_SIZE);

#ifdef DEBUG
          printf("Got a %d bytes IPv4 [iphdr_len=%d] packet\n", header.len, iphdr_len);
          printf("From %s (%s)\n", ip_buf, mac_buf);
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
                  inet_ntop(AF_INET, &ip_addr, ip_buf, IP_BUF_SIZE);

                  if(request.host_name_ptr != NULL) {
                    strncpy(name_buf, (char*)request.host_name_ptr, min(NAME_BUF_SIZE-1, request.host_name_len));
                    name_buf[min(NAME_BUF_SIZE-1, request.host_name_len)] = '\0';
                  }
#ifdef DEBUG
                  printf("DHCP REQUEST: %s %s\n", ip_buf, request.host_name_ptr ? name_buf : "");
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

                for(i=0; i<min(DNS_QUERY_SIZE-1, len); i++) {
                  char c = dns->queries[i];

                  if(!c)
                    break;
                  else if(c < ' ')
                    c = '.';

                  dns_query[i] = c;
                }

                dns_query[i] = '\0';
                //printf("DNS REQUEST: %s %s\n", ip_buf, dns_query);
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

typedef struct {
  PyObject_HEAD

  pcap_t *handle;
} pkt_readerObject;

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
  "A wrapper on the pcap handle",           /* tp_doc */
};

static PyObject *open_capture_dev(PyObject *self, PyObject *args) {
  const char *devname, *filter_exp;
  int read_timeout;
  int immediate_mode;
  pcap_t *handle;

  if (!PyArg_ParseTuple(args, "sisb", &devname, &read_timeout, &filter_exp, &immediate_mode))
    return NULL;

  handle = _open_capture_dev(devname, read_timeout, filter_exp, immediate_mode);

  if (!handle)
    return NULL;

  pkt_readerObject* wrapper;
  wrapper = (pkt_readerObject*) pkt_readerType.tp_new(&pkt_readerType, NULL, NULL);
  wrapper->handle = handle;

  if (! wrapper)
    return NULL;

  return (PyObject *)wrapper;
}

static PyObject *close_capture_dev(PyObject *self, PyObject *args) {
  pkt_readerObject *wrapper;

  if (!PyArg_ParseTuple(args, "O", &wrapper))
    return NULL;

  _close_capture_dev(wrapper->handle);
  Py_DECREF(wrapper);

  return Py_BuildValue("s", NULL);
}

static PyObject *read_packet_info(PyObject *self, PyObject *args) {
  PyObject *dict;
  pkt_readerObject *wrapper;
  char mac_buf[MAC_BUF_SIZE];
  char ip_buf[IP_BUF_SIZE];
  char name_buf[NAME_BUF_SIZE];
  char dns_buf[DNS_QUERY_SIZE];

  if (!PyArg_ParseTuple(args, "O", &wrapper))
    return NULL;

  mac_buf[0] = ip_buf[0] = name_buf[0] = dns_buf[0] = '\0';
  if (! _read_packet_info(wrapper->handle, mac_buf, ip_buf, name_buf, dns_buf))
    return Py_BuildValue("s", NULL);

  dict = PyDict_New();
  if (! dict)
    return NULL;

  if (mac_buf[0]) PyDict_SetItemString(dict, "mac", PyString_FromString(mac_buf));
  if (ip_buf[0]) PyDict_SetItemString(dict, "ip", PyString_FromString(ip_buf));
  if (name_buf[0]) PyDict_SetItemString(dict, "name", PyString_FromString(name_buf));
  if (dns_buf[0]) PyDict_SetItemString(dict, "query", PyString_FromString(dns_buf));

  return dict;
}

static PyMethodDef PktReaderMethods[] = {
  {"open_capture_dev",  open_capture_dev, METH_VARARGS, "Open a device for capture."},
  {"close_capture_dev", close_capture_dev, METH_VARARGS, "Closes a devices capture."},
  {"read_packet_info", read_packet_info, METH_VARARGS, "Read packet information. None is returned if no packet information is available."},
  {NULL, NULL, 0, NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC initpkt_reader() {
  if (PyType_Ready(&pkt_readerType) < 0)
    return;

  pkt_readerType.tp_new = PyType_GenericNew;

  Py_InitModule("pkt_reader", PktReaderMethods);
}

/* ************************************************************ */

//#define PKT_READER_AUTOTEST
#ifdef PKT_READER_AUTOTEST

int main(int argc, char *argv[]) {
  const char *devname = "wlan0";
  char mac_buf[MAC_BUF_SIZE];
  char ip_buf[IP_BUF_SIZE];
  char name_buf[NAME_BUF_SIZE];
  char dns_buf[DNS_QUERY_SIZE];

  pcap_t *dev = _open_capture_dev(devname, 1000, "broadcast or arp", 0);

  if (dev != NULL) {
    printf("Capturing packets on %s...\n", devname);

    while(1) {
      mac_buf[0] = '\0';
      name_buf[0] = '\0';

      if (_read_packet_info(dev, mac_buf, ip_buf, name_buf, dns_buf)) {
        printf("+ Seen %s as %s [name=%s][dns=%s]\n", mac_buf, ip_buf, name_buf, dns_buf);
      }
    }

    _close_capture_dev(dev);
  }

  return(0);
}

#endif
