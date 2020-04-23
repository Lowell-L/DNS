# DNS
Simulate DNS--NUAA's Computer network experiment

## 主要功能
1. 模拟一个 DNS 本地域名服务器，接收来自客户端的 DNS 报文请求；
2. 首先本地查询：查询本地地址表，若存在相应 IP 地址，构建响应报文返回；
3. 若不存在相应 IP 地址，在线查询：根据客户端设置进行递归（复合）和迭代查询，与根服务器等进行交互，最终得到相应的 IP 地址；
4. 在线查询后将此项记录写入本地文件；

## 实验数据

可以支持在线查询北大、东大等大学的 IP 地址；对于百度、淘宝、哔哩哔哩等商业公司，因其域名存在别名，为实现查询此类域名的 IP 地址。

## 项目环境
C/C++ VS2015 Socket
