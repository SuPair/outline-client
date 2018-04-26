// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO: make import order irrelevant!
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
// clang-format on

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

void usage(const char* path) {
  printf("usage: on|off <ip of new gateway> <ip of shadowsocks server>\n");
  exit(1);
}

// while the route command will figure out the best interface,
// these API calls do not.
DWORD getBest(DWORD ip) {
  DWORD best;
  DWORD dwStatus = GetBestInterface(ip, &best);
  if (dwStatus != NO_ERROR) {
    printf("could not figure best interface for IP: %d\n", dwStatus);
    exit(1);
  }
  return best;
}

DWORD getInterfaceMetric(DWORD interfaceIndex) {
  MIB_IPINTERFACE_ROW ipInterfaceRow = {0};
  ipInterfaceRow.Family = AF_INET;
  ipInterfaceRow.InterfaceIndex = interfaceIndex;
  DWORD dwStatus = GetIpInterfaceEntry(&ipInterfaceRow);
  if (dwStatus != NO_ERROR) {
    printf("could not call GetIpInterfaceEntry: %d\n", dwStatus);
    exit(1);
  }
  return ipInterfaceRow.Metric;
}

PMIB_IPFORWARDROW createRowForSingleIp() {
  PMIB_IPFORWARDROW row = (PMIB_IPFORWARDROW)malloc(sizeof(MIB_IPFORWARDROW));
  if (!row) {
    printf("Malloc failed. Out of memory.\n");
    exit(1);
  }

  // all fields:
  // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366850(v=vs.85).aspx
  row->dwForwardDest = 0;
  row->dwForwardMask = 0xFFFFFFFF;  // 255.255.255.255
  row->dwForwardPolicy = 0;
  row->dwForwardNextHop = 0;
  row->dwForwardIfIndex = 0;
  row->dwForwardType = 4;  /* the next hop is not the final dest */
  row->dwForwardProto = 3; /* PROTO_IP_NETMGMT */
  row->dwForwardAge = 0;
  row->dwForwardNextHopAS = 0;
  row->dwForwardMetric1 = 0;
  row->dwForwardMetric2 = 0;
  row->dwForwardMetric3 = 0;
  row->dwForwardMetric4 = 0;
  row->dwForwardMetric5 = 0;

  return row;
}

// TODO handle host names
int main(int argc, char* argv[]) {
  if (argc < 4) {
    usage(argv[0]);
  }

  int connecting = strcmp(argv[1], "on") == 0;

  DWORD NewGateway = INADDR_NONE;
  NewGateway = inet_addr(argv[2]);
  if (NewGateway == INADDR_NONE) {
    printf("could not parse gateway IP\n");
    return 1;
  }

  DWORD proxyServerIp = INADDR_NONE;
  proxyServerIp = inet_addr(argv[3]);
  if (proxyServerIp == INADDR_NONE) {
    printf("could not parse proxy IP\n");
    return 1;
  }

  // TODO: remove this once our tun2socks supports UDP
  DWORD dnsIp = inet_addr("8.8.8.8");

  // Fetch the system's routing table.
  PMIB_IPFORWARDTABLE pIpForwardTable = (MIB_IPFORWARDTABLE*)MALLOC(sizeof(MIB_IPFORWARDTABLE));
  if (pIpForwardTable == NULL) {
    printf("Error allocating memory\n");
    return 1;
  }

  DWORD dwSize = 0;
  if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
    FREE(pIpForwardTable);
    pIpForwardTable = (MIB_IPFORWARDTABLE*)MALLOC(dwSize);
    if (pIpForwardTable == NULL) {
      printf("Error allocating memory\n");
      return 1;
    }
  }

  if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) != NO_ERROR) {
    printf("could not query routing table\n");
    FREE(pIpForwardTable);
    return 1;
  }

  // default gateway.
  PMIB_IPFORWARDROW pRow = NULL;
  // proxy server.
  PMIB_IPFORWARDROW proxyRow = NULL;
  // DNS server.
  PMIB_IPFORWARDROW dnsRow = NULL;

  for (int i = 0; i < pIpForwardTable->dwNumEntries; i++) {
    if (pIpForwardTable->table[i].dwForwardDest == 0) {
      if (pRow) {
        printf("sorry, cannot handle multiple default gateways\n");
        exit(1);
      }
      pRow = &(pIpForwardTable->table[i]);
    } else if (pIpForwardTable->table[i].dwForwardDest == proxyServerIp) {
      if (proxyRow) {
        printf("found multiple routes to proxy server, cannot handle\n");
        exit(1);
      }
      printf("found route to proxy server, can modify\n");
      proxyRow = &(pIpForwardTable->table[i]);
    } else if (pIpForwardTable->table[i].dwForwardDest == dnsIp) {
      if (dnsRow) {
        printf("found multiple routes to DNS server, cannot handle\n");
        exit(1);
      }
      printf("found route to DNS server, can modify\n");
      dnsRow = &(pIpForwardTable->table[i]);
    }
  }

  DWORD dwStatus = 0;

  if (!pRow) {
    printf("no default gateway - are you connected to the internet?\n");
    exit(1);
  }

  // remember the old gateway: traffic to the proxy and DNS servers will
  // still route via it.
  DWORD oldGateway = pRow->dwForwardNextHop;

  // which interfaces are the old and new gateway on?
// NOTE: for the new gateway, tun2socks must be active before
// getBest will work!
  int oldGatewayInterfaceIndex = getBest(oldGateway);
  int newGatewayInterfaceIndex = getBest(NewGateway);

  printf("old gateway interface index: %d\n", oldGatewayInterfaceIndex);
  printf("new gateway interface index: %d\n", newGatewayInterfaceIndex);

  // print the old gateway.
  char oldGatewayIp[128];
  struct in_addr IpAddr;
  IpAddr.S_un.S_addr = (u_long)pRow->dwForwardNextHop;
  strcpy(oldGatewayIp, inet_ntoa(IpAddr));
  printf("current gateway: %s\n", oldGatewayIp);

  DWORD oldGatewayInterfaceMetric = getInterfaceMetric(oldGatewayInterfaceIndex);
  DWORD newGatewayInterfaceMetric = getInterfaceMetric(newGatewayInterfaceIndex);

  printf("old gateway interface metric: %d\n", oldGatewayInterfaceMetric);
  printf("new gateway interface metric: %d\n", newGatewayInterfaceMetric);

  PMIB_IPFORWARDROW gwRow = createRowForSingleIp();
  gwRow->dwForwardDest = 0;
  gwRow->dwForwardMask = 0;
  gwRow->dwForwardPolicy = 0;
  gwRow->dwForwardNextHop = NewGateway;
  gwRow->dwForwardIfIndex = newGatewayInterfaceIndex;
  gwRow->dwForwardType = 4;  /* the next hop is not the final dest */
  gwRow->dwForwardProto = 3; /* PROTO_IP_NETMGMT */
  gwRow->dwForwardAge = 0;
  gwRow->dwForwardNextHopAS = 0;
  // TODO: should this be computed in relation to the old gateway's interface metric?
  gwRow->dwForwardMetric1 = newGatewayInterfaceMetric;
  gwRow->dwForwardMetric2 = 0;
  gwRow->dwForwardMetric3 = 0;
  gwRow->dwForwardMetric4 = 0;
  gwRow->dwForwardMetric5 = 0;

  dwStatus = CreateIpForwardEntry(gwRow);
  if (dwStatus != NO_ERROR) {
    printf("could not create new gateway: %d\n", dwStatus);
    exit(1);
  }
  printf("set new gateway\n");

  // Delete the old default gateway entry.
  dwStatus = DeleteIpForwardEntry(pRow);
  if (dwStatus != NO_ERROR) {
    printf("could not remove current gateway\n");
    exit(1);
  }
  printf("removed current gateway\n");

  // Add a route to the proxy server.
  if (proxyRow) {
    dwStatus = DeleteIpForwardEntry(proxyRow);
    if (dwStatus != ERROR_SUCCESS) {
      printf("could not delete current route to proxy server\n");
      exit(1);
    }
    printf("deleted old route to proxy server\n");
  }

  if (connecting) {
    proxyRow = createRowForSingleIp();
    proxyRow->dwForwardDest = proxyServerIp;
    proxyRow->dwForwardNextHop = oldGateway;
    proxyRow->dwForwardMetric1 = pRow->dwForwardMetric1;
    proxyRow->dwForwardIfIndex = oldGatewayInterfaceIndex;

    dwStatus = CreateIpForwardEntry(proxyRow);
    if (dwStatus != NO_ERROR) {
      printf("could not add route to proxy server: %d\n", dwStatus);
      exit(1);
    }
    printf("added new route to proxy server\n");
  }

  // Add a route to the DNS server.
  if (dnsRow) {
    dwStatus = DeleteIpForwardEntry(dnsRow);
    if (dwStatus != ERROR_SUCCESS) {
      printf("Could not delete old route to DNS server\n");
      exit(1);
    }
    printf("deleted old route to DNS server\n");
  }

  if (connecting) {
    dnsRow = createRowForSingleIp();
    dnsRow->dwForwardDest = dnsIp;
    dnsRow->dwForwardNextHop = oldGateway;
    dnsRow->dwForwardMetric1 = pRow->dwForwardMetric1;
    dnsRow->dwForwardIfIndex = oldGatewayInterfaceIndex;

    dwStatus = CreateIpForwardEntry(dnsRow);
    if (dwStatus != NO_ERROR) {
      printf("could not add route to DNS server: %d\n", dwStatus);
      exit(1);
    }
    printf("added new route to DNS server\n");
  }

  exit(0);
}
