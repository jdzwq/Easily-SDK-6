--macos
sudo cp -rf ./templ/macos/xportd.config /usr/local/Easily/sbin
sudo cp -rf ./templ/macos/xtimerd.config /usr/local/Easily/sbin
sudo cp -rf ./templ/macos/cfg /usr/local/Easily/sbin
sudo cp -rf ./templ/macos/crt /usr/local/Easily/sbin

-macos
vi ~/.zshrc
export XSERVICE_ROOT="/usr/local/Easily/sbin"
export XSERVICE_DATA="/usr/local/Easily/sbin/nfs"
export PATH="/usr/local/Easily/sbin/api:$PATH"
source ~/.zshrc

--macos
sudo vi /etc/paths
>> /usr/local/lib
