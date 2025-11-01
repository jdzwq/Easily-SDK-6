
--windows
export XSERVICE_ROOT="C:\Easily\xService"
export XSERVICE_DATA="C:\Easily\xService\nfs"
set Path = C:\Easily\lib;C:\Easily\sbin\api;%Path%

sc create xService binPath= "C:\Easily\sbin\xService.exe" start= demand DisplayName= "Easily Port Service"
sc start xService
sc delete xService