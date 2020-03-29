/*
 * ARP scan original code by Jason Ish. Adapted by Emanuele Faranda.
 *
 * Copyright (c) 2002-2003 Jason Ish <jason@codemonkey.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors and copyright holders may not be used to
 *    endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <Python.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dnet.h>

struct ether_arp {
  struct arp_hdr arp_hdr;
  struct arp_ethip arp_ethip;
};

typedef struct working_data {
  u_int32_t my_ipaddr;
  uint8_t my_ethaddr[6];
  eth_t *eth;
} working_data;

static void _init_dnet(working_data *wdata, const char *dev_name) {
  intf_t *dnet_if;
  struct intf_entry entry;

  dnet_if = intf_open();
  memset(&entry, 0, sizeof(entry));
  strncpy(entry.intf_name, dev_name, INTF_NAME_LEN - 1);
  intf_get(dnet_if, &entry);
  memcpy(&wdata->my_ipaddr, &entry.intf_addr.addr_ip, sizeof(u_int32_t));
  memcpy(&wdata->my_ethaddr, &entry.intf_link_addr.addr_eth, sizeof(wdata->my_ethaddr));
  intf_close(dnet_if);

  wdata->eth = eth_open(dev_name);
}

static void _finish_dnet(working_data *wdata) {
  eth_close(wdata->eth);
}

static void _send_arp(working_data *wdata, u_int32_t ip) {
  eth_t *eth = wdata->eth;
  struct eth_hdr eth_header;
  u_char pkt[sizeof(struct eth_hdr) + sizeof(struct ether_arp)];
  struct ether_arp *arp;

  memset(&eth_header.eth_dst, 0xff, sizeof(eth_header.eth_dst));
  memcpy(&eth_header.eth_src, wdata->my_ethaddr, sizeof(wdata->my_ethaddr));
  eth_header.eth_type = htons(ETH_TYPE_ARP);

  memset(pkt, 0, sizeof(pkt));
  memcpy(pkt, &eth_header, sizeof(eth_header));

  arp = (struct ether_arp *)(pkt + sizeof(struct eth_hdr));
  arp->arp_hdr.ar_hrd = htons(ARP_HRD_ETH);
  arp->arp_hdr.ar_pro = htons(ETH_TYPE_IP);
  arp->arp_hdr.ar_hln = ETH_ADDR_LEN;
  arp->arp_hdr.ar_pln = sizeof(ip);
  arp->arp_hdr.ar_op = htons(ARP_OP_REQUEST);

  memcpy(&arp->arp_ethip.ar_sha, &eth_header.eth_src,
      sizeof(eth_header.eth_src));
  memcpy(&arp->arp_ethip.ar_spa, &wdata->my_ipaddr, sizeof(u_int32_t));
  memcpy(&arp->arp_ethip.ar_tpa, &ip, sizeof(u_int32_t));

  eth_send(eth, (void *)pkt, sizeof(pkt));
}

static void _arp_scan(working_data *data, u_int32_t first_ip, u_int32_t last_ip) {
  u_int32_t cur_ip;

  cur_ip = first_ip;

  while (ntohl(cur_ip) <= ntohl(last_ip)) {
    _send_arp(data, cur_ip);
    cur_ip = htonl(ntohl(cur_ip) + 1);
  }
}

static int _get_scan_range(char *network_range, u_int32_t *first_ip, u_int32_t *last_ip) {
  u_int32_t subnet;
  u_int32_t netmask;
  int bitmask;

  char *slash = strchr(network_range, '/');
  if (! slash) return 0;

  *slash++ = '\0';
  subnet = inet_addr(network_range);
  if (subnet == INADDR_NONE) return 0;

  subnet = ntohl(subnet);
  bitmask = atoi(slash);
  if (bitmask < 1 || bitmask > 32) return 0;

  netmask = 0xffffffff << (32 - bitmask);
  *first_ip = htonl(subnet & netmask);
  *last_ip = htonl(subnet | ~netmask);

  return 1;
}

/* ************************************************************ */

typedef struct {
  PyObject_HEAD

  working_data *handle;
} arp_scannerObject;

static PyTypeObject arp_scannerType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "arp_scanner",              /* tp_name */
  sizeof(arp_scannerObject),  /* tp_basicsize */
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
  "ARP scanner status",           /* tp_doc */
};

static PyObject *init_scanner(PyObject *self, PyObject *args) {
  const char *devname;
  working_data *handle;

  if (!PyArg_ParseTuple(args, "s", &devname))
    return NULL;

  handle = (working_data *) calloc(1, sizeof(working_data));
  if (!handle) return NULL;

  _init_dnet(handle, devname);
  if (handle->eth == NULL) {
    free(handle);
    return NULL;
  }

  arp_scannerObject* wrapper;
  wrapper = (arp_scannerObject*) arp_scannerType.tp_new(&arp_scannerType, NULL, NULL);
  wrapper->handle = handle;
  if (! wrapper) return NULL;

  return (PyObject *)wrapper;
}

static PyObject *scan_ip(PyObject *self, PyObject *args) {
  arp_scannerObject *wrapper;
  char *ip_to_scan;
  u_int32_t ip;

  if (!PyArg_ParseTuple(args, "Os", &wrapper, &ip_to_scan))
    return NULL;

  ip = inet_addr(ip_to_scan);
  if (ip == INADDR_NONE) return 0;
  _send_arp(wrapper->handle, ip);

  return Py_BuildValue("s", NULL);
}

static PyObject *scan_network(PyObject *self, PyObject *args) {
  arp_scannerObject *wrapper;
  char *net_to_scan;
  u_int32_t first_ip, last_ip;
  char netbuf[32];

  if (!PyArg_ParseTuple(args, "Os", &wrapper, &net_to_scan))
    return NULL;

  strncpy(netbuf, net_to_scan, sizeof(netbuf));
  netbuf[sizeof(netbuf)-1] = '\0';

  if (!_get_scan_range(netbuf, &first_ip, &last_ip))
    return NULL;

  _arp_scan(wrapper->handle, first_ip, last_ip);

  return Py_BuildValue("s", NULL);
}

static PyObject *finish_scanner(PyObject *self, PyObject *args) {
  arp_scannerObject *wrapper;

  if (!PyArg_ParseTuple(args, "O", &wrapper))
    return NULL;

  _finish_dnet(wrapper->handle);
  free(wrapper->handle);
  Py_DECREF(wrapper);

  return Py_BuildValue("s", NULL);
}

static PyMethodDef ArpScannerMethods[] = {
  {"init_scanner",  init_scanner, METH_VARARGS, "Initializes the ARP scanner."},
  {"scan_ip", scan_ip, METH_VARARGS, "Scan a single IP address."},
  {"scan_network", scan_network, METH_VARARGS, "Scan a whole network in CIDR format."},
  {"finish_scanner",  finish_scanner, METH_VARARGS, "Finalizes the ARP scanner."},
  {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyMODINIT_FUNC PyInit_arp_scanner() {
  if (PyType_Ready(&arp_scannerType) < 0)
    return(NULL);

  arp_scannerType.tp_new = PyType_GenericNew;

  static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "arp_scanner", NULL /* doc */, -1, ArpScannerMethods,
  };

  return(PyModule_Create(&moduledef));
}

/* ************************************************************ */

//#define ARP_SCANNER_AUTOTEST
#ifdef ARP_SCANNER_AUTOTEST

int main(int argc, char **argv) {
  u_int32_t first_ip = 0;
  u_int32_t last_ip = 0;
  char *dev_name = "wlan0";
  char network_range[32] = "192.168.1.6/24";
  working_data wdata;

  if (! _get_scan_range(network_range, &first_ip, &last_ip)) {
    fprintf(stderr, "Cannot get scan range\n");
    return 1;
  }

  _init_dnet(&wdata, dev_name);
  if (wdata.eth == NULL) {
    fprintf(stderr, "Failed to open %s\n", dev_name);
    return 1;
  }

  printf("Scanning %u-%u\n", ntohl(first_ip), ntohl(last_ip));
  _arp_scan(&wdata, first_ip, last_ip);

  _finish_dnet(&wdata);

  return 0;
}

#endif
