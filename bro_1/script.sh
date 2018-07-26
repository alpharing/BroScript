bro -C -r ../sample/ftpcrack.pcap test1.bro
grep Bruteforcing notice.log > ftp_crack.log
grep Bruteforcing notice.log | awk '{print $11 " is detected"}'
grep Bruteforcing notice.log | awk '{print $12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22}'
