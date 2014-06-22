openssl_openwrt: main.c
	../../mips-openwrt-linux-g++ -std=c++0x -pthread -I/mnt/vdc/openwrt/attitude_adjustment/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/include -L/mnt/vdc/openwrt/attitude_adjustment/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/lib main.c -o openssl_openwrt -lssl -lcrypto

# slave_openwrt: main.o slave.o tool.o timer.o
# 	../../mips-openwrt-linux-g++ -std=c++0x -I/mnt/vdc/openwrt/attitude_adjustment/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/include -L/mnt/vdc/openwrt/attitude_adjustment/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/lib main.o slave.o timer.o tool.o -o slave_openwrt -lasound

# main.o: main.cpp
# 	../../mips-openwrt-linux-g++ -std=c++0x -c main.cpp

# slave.o: slave.cpp slave.h tool.o timer.o
# 	../../mips-openwrt-linux-g++ -std=c++0x -I/mnt/vdc/openwrt/attitude_adjustment/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/include -c slave.cpp

# tool.o: tool.cpp tool.h
# 	../../mips-openwrt-linux-g++ -std=c++0x -c tool.cpp

# timer.o: timer.cpp timer.h
# 	../../mips-openwrt-linux-g++ -std=c++0x -c timer.cpp

clean:
	rm openssl_openwrt
