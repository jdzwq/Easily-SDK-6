--linux
sudo cp -rf ./templ/linux/xportd.config /usr/local/Easily/sbin
sudo cp -rf ./templ/linux/xtimerd.config /usr/local/Easily/sbin
sudo cp -rf ./templ/linux/cfg /usr/local/Easily/sbin
sudo cp -rf ./templ/linux/crt /usr/local/Easily/sbin
sudo cp -rf ./templ/linux/loc /usr/local/Easily/sbin
sudo cp -rf ./templ/linux/www /usr/local/Easily/sbin
sudo cp -rf ./templ/linux/nfs /usr/local/Easily/sbin

sudo chmod -R 644 ./usr/local/Easily/sbin/cfg
sudo chmod -R 644 ./usr/local/Easily/sbin/crt
sudo chmod -R 644 ./usr/local/Easily/sbin/loc
sudo chmod -R 644 ./usr/local/Easily/sbin/www
sudo chmod -R 666 ./usr/local/Easily/sbin/nfs
...

-linux
vi ~/.bashrc
export XSERVICE_ROOT="/usr/local/Easily/sbin"
export XSERVICE_DATA="/usr/local/Easily/sbin/nfs"
export PATH="/usr/local/Easily/sbin/api:$PATH"
source ~/.bashrc

sudo vi /etc/ld.so.conf
/usr/local/lib
sudo ldconfig

--linux
sudo systemctl enable xportd.service
systemctl daemon-reload
systemctl list-unit-files
systemctl start xportd.service
systemctl stop xportd.service
systemctl reload xportd.service
systemctl status xportd.service