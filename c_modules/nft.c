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
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <nftables/libnftables.h>

#include "netutils.c"

/* ************************************************************ */

/* NOTE: directly running nft with os.execute won't work because of
 * the dropped privileges. libnftables instead works with linux capabilities. */
static PyObject *run_nft_cmd(PyObject *self, PyObject *args) {
  const char *cmd;
  struct nft_ctx *nft;
  
  if (!PyArg_ParseTuple(args, "s", &cmd))
    return NULL;

  if(!(nft = nft_ctx_new(NFT_CTX_DEFAULT))) {
    fprintf(stderr, "nft_ctx_new failed\n");
    return NULL;
  }

#if 1
  if(nft_run_cmd_from_buffer(nft, cmd))
#else
  if(nft_run_cmd_from_buffer(nft, (char*)cmd, strlen(cmd)))
#endif
{
    nft_ctx_free(nft);
    Py_RETURN_FALSE;
  }

  nft_ctx_free(nft);
  Py_RETURN_TRUE;
}

/* ************************************************************ */

static PyObject *get_iface_ip(PyObject *self, PyObject *args) {
  const char *iface;
  struct in_addr addr;
  uint32_t netmask;

  if (!PyArg_ParseTuple(args, "s", &iface))
    return NULL;

  if(get_interface_ip_address(iface, &addr.s_addr, &netmask) != -1)
    return PyUnicode_FromString(inet_ntoa(addr));

  Py_RETURN_NONE;
}

/* ************************************************************ */

static PyMethodDef nfwMethods[] = {
  {"run", run_nft_cmd, METH_VARARGS, "Run nftables commands"},
  {"get_iface_ip", get_iface_ip, METH_VARARGS, "Get an interface IP address"},
  {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyMODINIT_FUNC PyInit_nft() {
  static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "nft", NULL /* doc */, -1, nfwMethods,
  };

  return(PyModule_Create(&moduledef));
}
