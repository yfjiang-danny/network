# Network Learning

Network Reference

**QA**

1. `pcap.h: No such file or directory` -> Missing lib `libpcap`,then install **libpcap**

   `Ubuntu / Debian:`

   ```bash
   sudo apt-get update
   sudo apt-get install libpcap-dev
   ```

   `Red Hat / CentOS:`

   ```bash
   sudo yum install libpcap-devel
   ```

   `macOS:`

   ```bash
   brew install libpcap
   ```

   `Windows:`
   use `WinPcap` or `Npcap`

2. `You don't have permission to capture on that device (socket: Operation not permitted)`

   Use sudo: `sudo /usr/local/go/bin/go run your_program.go `, make sure `/usr/local/go/bin/go` is your go path, you can use `which go` to get it.
