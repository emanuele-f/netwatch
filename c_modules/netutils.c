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

#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>

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
