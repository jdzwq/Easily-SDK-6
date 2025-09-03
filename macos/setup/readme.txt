
-macos
cd /usr/local/xService
vi ~/.bash_profile
export XSERVICE_ROOT="/usr/local/xService"
export XSERVICE_DATA="/usr/local/xService/nfs"
source ~/.bash_profile

--macos
sudo vi /etc/paths
>> /usr/local/lib
>> /usr/local/xService/api

sudo systemctl enable xportd.service
systemctl daemon-reload
systemctl list-unit-files
systemctl start xportd.service
systemctl stop xportd.service
systemctl reload xportd.service
systemctl status xportd.service