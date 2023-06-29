# DNSrelay

## Requirement
MinGW 64, gcc 8.1
windows 10
### 关闭svchost.exe对53号端口的占用
禁用Host Network Service后，关闭该服务
再禁用Internet Connection Sharing(ICS)后，关闭该服务
（注意，两者的顺序不能乱，因为ICS服务依赖于HNS服务，直接关闭ICS会出现不能关闭该服务的错误提示）

在cmd命令行下运行
```netstat -ano |findstr ":53"```
检查53号端口是否被占用（这个命令会筛选出所有53开头的端口号，只需要关注53号就好了），如果还是被占用，可以记住端口号，试着在任务管理器里关闭，但这对系统服务无效，因为关了还是会重新打开，这时候可以用下面这个命令
```tasklist```
检查所有进程pid对应的系统服务名，然后去任务管理器里找到该系统服务名，通过谷歌等方式，找到提供该服务的系统服务，关闭其即可


## Execution
```
gcc main.c DNSpacket.c DNSSerilizer.c DNSparser.c DNSsocket.c Debugger.c PendingQuery.c -lwsock32 -lws2_32  -o main
main
```

## Example
新开一个命令行，运行以下命令进行测试
```
nslookup www.baidu.com 127.
0.0.1
```