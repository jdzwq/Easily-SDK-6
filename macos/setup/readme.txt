--macos
sudo cp -rf ./templ/xService/* /usr/local/xService

-macos
cd /usr/local/xService
vi ~/.zshrc
export XSERVICE_ROOT="/usr/local/xService"
export XSERVICE_DATA="/usr/local/xService/nfs"
source ~/.zshrc

--macos
sudo vi /etc/paths
>> /usr/local/lib
>> /usr/local/xService/api
