cd httpd-2.4.49
PREFIX=/home/bill/APG/testcase/cve_21773/apache2.4.49
EXTRA_CFLAGS="-g" ./configure --prefix=$PREFIX
make
make install
cd ..
