#include <sys/sysinfo.h>
#include <stdio.h>
#include "logger.h"
#include "wb_system.h"

#define SYSINFO_CONVERSION 65536.0

int get_cpu_load(double loadavg[3]){
    //double loadavg[3];

    struct sysinfo sys_info;

    if(sysinfo(&sys_info) != 0){
        wblprintf(LOG_WARNING,"CPU_USAGE","Error, could not obtain CPU usage info\n");
        return SYS_INFO_ERROR;
    }

    loadavg[0]=(sys_info.loads[0]/SYSINFO_CONVERSION);
    loadavg[1]=(sys_info.loads[1]/SYSINFO_CONVERSION);
    loadavg[2]=(sys_info.loads[2]/SYSINFO_CONVERSION);

    return SYS_INFO_OK;
}

/*
int main() {
  int days, hours, mins;
  struct sysinfo sys_info;

  if(sysinfo(&sys_info) != 0)
    perror("sysinfo");

  
  days = sys_info.uptime / 86400;
  hours = (sys_info.uptime / 3600) - (days * 24);
  mins = (sys_info.uptime / 60) - (days * 1440) - (hours * 60);

  printf("Uptime: %ddays, %dhours, %dminutes, %ldseconds\n",
                      days, hours, mins, sys_info.uptime % 60);
  
  printf("Load Avgs: 1min(%2.2lf) 5min(%2.2lf) 15min(%2.2lf)\n",
          (sys_info.loads[0]/SYSINFO_CONVERSION), (sys_info.loads[1]/SYSINFO_CONVERSION),
          (sys_info.loads[2]/SYSINFO_CONVERSION));

  printf("Total Ram: %lluk\tFree: %lluk\n",
                sys_info.totalram *(unsigned long long)sys_info.mem_unit / 1024,
                sys_info.freeram *(unsigned long long)sys_info.mem_unit/ 1024);


  // Number of processes currently running.
  printf("Number of processes: %d\n", sys_info.procs);

  return 0;
}
*/