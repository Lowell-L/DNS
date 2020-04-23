#include <stdio.h>
#include <winsock2.h>
#include<stdio.h>
#include<iostream>
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>
#include <winsock2.h>
using namespace std;

#pragma comment(lib, "ws2_32.lib") 
#pragma warning(disable:4996)
#define BUF_SIZE 1024

typedef struct dns_header
{
	uint16_t transactionID;	//会话标识
	
	//Flags
	uint8_t RD : 1;		//表示期望递归
	uint8_t TC : 1;		//表示可截断的
	uint8_t AA : 1;		//表示授权回答
	uint8_t opcode : 4;	//0表示标准查询，1表示反向查询，2表示服务器状态请求
	uint8_t QR : 1;		//查询/响应标志，0为查询，1为响应
	uint8_t rcode : 4;	//表示返回码，0表示没有差错，3表示名字差错，2表示服务器错误
	uint8_t: 3;
	uint8_t RA : 1;		//表示可用递归

	uint16_t questions;	//问题数
	uint16_t answerRRs;	//
	uint16_t authorityRRs;
	uint16_t additionalRRs;
} DNS_HEADER;

#pragma pack(push, 1)//保存对齐状态，设定为1字节对齐(TTL元素 4字节对齐会有问题)
/*
typedef struct dns_answers
{
	uint16_t name;			//域名（偏移指针 0xC00C）
	uint16_t query_type;	//查询类型
	uint16_t query_class;	//查询类
	uint32_t TTL;			//Time to live
	uint16_t dataLength;	//资源数据长度
	//4字节对齐问题！！！！！！！！！！！！！！
	
	//资源数据（IP地址）
	uint8_t data1;
	uint8_t data2;
	uint8_t data3;
	uint8_t data4;

}DNS_ANSWERS;
*/
typedef struct resource_Record
{
	uint16_t name;			//域名（偏移指针 0xC00C）
	uint16_t query_type;	//查询类型
	uint16_t query_class;	//查询类
	uint32_t TTL;			//Time to live
	uint16_t dataLength;	//资源数据长度
	uint8_t data[];			//资源数据
}RR;
#pragma pack(pop) //恢复对齐状态

int Socket();
int DNS(char *receive_message, char* send_message, int receive_length);
int buildDomainName(char *receive_message, char* DomainName);
int localFind(char * DomainName, char* IP);
int buildSendMessage(char* receive_message, char* send_message, char* IP, int receive_length);
void strtobit(char *chr);
int onlineFind(char* root_IP, char* send_message1, char* receive_message1, int send_length1, char* IP1);
int dealReceiveMessage(char* receive_message, char* IP, int send_length, int receive_length);
int buildIP(char* integerIP, char* stringIP);

int main(int argc, char* argv[])
{
	Socket();
	system("pause");
}

int Socket() {
	//1.请求版本协议
	WORD socketVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	WSAStartup(socketVersion, &wsaData);
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		printf("请求协议版本失败！\n");
		return -1;
	}
	else printf("请求协议版本成功！\n");

	//2.创建socket
	SOCKET server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (server_socket == SOCKET_ERROR) {
		printf("创建socket失败！\n");
		WSACleanup();
		return -2;
	}
	else printf("创建socket成功！\n");

	//3.创建协议地址族：IP地址及端口
	SOCKADDR_IN server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;			//协议版本
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(53);

	//4.绑定
	if (-1 == bind(server_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) ){
		printf("绑定失败！\n");
		closesocket(server_socket);
		WSACleanup();
		return -3;
	}
	else printf("绑定成功！\n");

	//5. 发送接收
	SOCKADDR_IN client_addr;
	int client_addr_length = sizeof(client_addr);
	
	char receive_message[BUF_SIZE];
	char send_message[BUF_SIZE];

	while (true) {
		printf("\n等待用户连接……\n");

		//接收数据
		int receive_length = recvfrom(server_socket, receive_message, BUF_SIZE, 0, (sockaddr*)&client_addr, &client_addr_length);
		if (receive_length == -1) {
			printf("接收失败！\n");
			break;
		}
		else printf("接收到 %d 个字节！\n", receive_length);
		
//调试所用
//memset(send_message, 0, BUF_SIZE);
//strcpy(send_message, "一个来自服务端的UDP数据包\n\0");

		//处理DSN报文，查询并将结果写入发送报文send_message中
		int send_length = DNS(receive_message, send_message, receive_length);

		//发送数据
		int real_send_length = sendto(server_socket, send_message, send_length, 0, (sockaddr *)&client_addr, client_addr_length);
		if (real_send_length == -1) {
			printf("发送失败！\n");
			return -4;
		}
		else printf("成功发送 %d 个字节！\n", real_send_length);
	}

	//6.关闭套接字
	closesocket(server_socket);
	WSACleanup();
	
	system("pause");
	return 0;
}

/*
 * 功能：    模拟DNS
 * 输入参数：receive_message	请求报文
 *			 send_message		响应报文
 *			 receive_length		请求报文长度
 * 返回值：  类型(int)			表示构建的响应报文的长度
 * 简介：	 首先根据函数 buildDomainName 处理接收到的DNS报文，从中得到点分十进制形式的域名字符串；
 *			 然后调用函数 localFind 在本地查找此域名对应的IP地址；
 *			 如果找到，则调用函数 buildSendMessage 构建发送报文；
 *			 如果找不到
*/
int DNS(char *receive_message, char* send_message, int receive_length){
	char DomainName[256];								//存储域名
	char IP[50];										//存储IP地址的整数
	buildDomainName(receive_message+12, DomainName);		//抽取域名
	int send_length = 0;								//响应报文长度；

	//本地查询找到，构建响应报文
	if (localFind(DomainName, IP) == 1) {
		send_length = buildSendMessage(receive_message, send_message, IP, receive_length);
	}

	//本地查询不到
	else {
		printf("本地未查询到！\n");

		char root_IP[50];
		printf("请输入根域名服务器的IP地址：\n");
		scanf("%s", root_IP);

		char receive_message1[BUF_SIZE];
		char send_message1[BUF_SIZE];
		char IP1[50];
		int send_length1 = receive_length;		//复制发送长度
		for (int i = 0; i < send_length1; i++)	//复制发送报文
			send_message1[i] = receive_message[i];
		//调试所用
		//strtobit(receive_message);
		//strtobit(send_message1);
		if (((DNS_HEADER*)send_message1)->RD == 1) {
			//复合查询
			while (true) {
				int flag = onlineFind(root_IP, send_message1, receive_message1, send_length1, IP1);
				if (flag < 0) {
					printf("查询失败\n");
					system("pause");
					exit(0);
				}
				else if (flag == 0) {
					memset(root_IP, 0, 50);
					buildIP(IP1, root_IP);
					continue;
				}
				else if (flag == 1) {
					break;
				}
			}
			send_length = buildSendMessage(receive_message, send_message, IP1, receive_length);
		}
		else {
			//迭代查询
			while (true) {
				int flag = onlineFind(root_IP, send_message1, receive_message1, send_length1, IP1);
				if (flag < 0) {
					printf("查询失败\n");
					system("pause");
					exit(0);
				}
				else if (flag == 0) {
					memset(root_IP, 0, 50);
					buildIP(IP1, root_IP);
					printf("按任意键向下一个服务器 %s 查询\n", root_IP);
					getchar(); getchar();
					continue;
				}
				else if (flag == 1) {
					break;
				}
			}
			send_length = buildSendMessage(receive_message, send_message, IP1, receive_length);
		}

		//将在线查询到的IP地址存储到文件中；
		FILE * fp;
		if ((fp = fopen("localAddress.txt", "a+")) == NULL) {
			printf("cannot open this file!\n");
			system("pause");
			exit(0);
		}
		printf("%s\n", DomainName);
		fprintf(fp, "%s %u %u %u %u\n", DomainName, (unsigned char)(IP1[0]), (unsigned char)(IP1[1]), (unsigned char)(IP1[2]), (unsigned char)(IP1[3]));
		fclose(fp);
	}

//调试所用
//strtobit(send_message);
	return send_length;
}

/*
 * 功能：根据请求报文中的域名建立域名字符串
 * 
 */
int buildDomainName(char *receive_message, char* DomainName){
	char * p = receive_message;
	int i = 0;

	while (*p != 0x0) {
		char num = *p;
		p = p + 1;
		while (num > 0) {
			DomainName[i] = *p;
			i++;
			p++;
			num--;
		}
		DomainName[i] = '.';
		i++;
	}
	DomainName[--i] = '\0';
	printf("得到域名：%s\n", DomainName);
	return 0;
}
	
//切割字符串
void split(char *src, const char *separator, char **dest, int *num) {
	/*
	src 源字符串的首地址(buf的地址)
	separator 指定的分割字符
	dest 接收子字符串的数组
	num 分割后子字符串的个数
	*/
	char *pNext;
	int count = 0;
	if (src == NULL || strlen(src) == 0) //如果传入的地址为空或长度为0，直接终止 
		return;
	if (separator == NULL || strlen(separator) == 0) //如未指定分割的字符串，直接终止 
		return;
	pNext = (char *)strtok(src, separator); //必须使用(char *)进行强制类型转换(虽然不写有的编译器中不会出现指针错误)
	while (pNext != NULL) {
		*dest++ = pNext;
		++count;
		pNext = (char *)strtok(NULL, separator);  //必须使用(char *)进行强制类型转换
	}
	*num = count;
}

//本地查询
int localFind(char * DomainName, char* IP) {
	int flag = 0;		//标志是否查询到 0为未查询到，1为查询到
	//打开文件
	FILE * fp;
	if ((fp = fopen("localAddress.txt", "a+")) == NULL) {
		printf("cannot open this file!\n");
		system("pause");
		exit(0);
	}

	char temp[300];		//存放文件的一行
	int num = 0;		//存放分割的字符串的个数
	char *revbuf[5] = { 0 };	//存放分割后的各部分
	
	while (fgets(temp, 300, fp) != NULL) {
		//调用函数进行分割 
		//split(temp, " ", revbuf, &num);
		//printf("%d\n", num);
		//for (int i = 0; i < num; i++)	//输出返回的每个内容
		//	printf("%s\n", revbuf[i]);
		if (strcmp(DomainName, strtok(temp, " ")) == 0) {
			flag = 1;	//找到
			IP[0] = (char)atoi((char *)strtok(NULL, " "));
			IP[1] = (char)atoi((char *)strtok(NULL, " "));
			IP[2] = (char)atoi((char *)strtok(NULL, " "));
			IP[3] = (char)atoi((char *)strtok(NULL, " "));
			printf("%u.%u.%u.%u\n", (unsigned char)IP[0], (unsigned char)IP[1], (unsigned char)IP[2], (unsigned char)IP[3]);
			break;
		}
		else continue;
	}
	fclose(fp);
	return flag;
}

//查询到IP地址，构建响应报文
int buildSendMessage(char* receive_message, char* send_message, char* IP, int receive_length) {
	//将查询报文复制到响应报文中
	for (int i = 0; i < receive_length; i++)
		send_message[i] = receive_message[i];
	
	DNS_HEADER* header = (DNS_HEADER*)send_message;
	header->QR = 1;		//1表示响应
	header->answerRRs = htons(1);

	RR* answers = (RR*)(send_message + receive_length);
	answers->name = htons(0xc00c);		//域名（偏移指针 0xC00C）32 33
	answers->query_type = htons(1);		
	answers->query_class = htons(1);
	answers->TTL = htonl (30);
	answers->dataLength = htons(4);
	answers->data[0] = IP[0];
	answers->data[1] = IP[1];
	answers->data[2] = IP[2];
	answers->data[3] = IP[3];

	return receive_length + 16;
}

//以二进制形式输出字符串。调试所用
void strtobit(char *chr)
{
	char *pchr = chr;
	int i, j;
	for (i = 0; i<50; i++)
	{
		printf("%d	", i + 1);
		for (j = 7; j >= 0; j--)
		{
			char tmpp = pchr[i];
			tmpp = pchr[i] & (1 << j);
			printf("%d", tmpp >> j);
		}
		printf("\n");
	}
}

//向目标服务器查询
int onlineFind(char* root_IP, char* send_message1, char* receive_message1,int send_length1, char* IP1) {
	printf("\n开始连接服务器 %s\n", root_IP);

	//1.请求版本协议
	WORD socketVersion = MAKEWORD(2, 2);	//版本
	WSADATA wsaData;
	WSAStartup(socketVersion, &wsaData);
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("请求版本协议失败！\n");
		return -1;
	}
	else printf("请求版本协议成功！\n");

	//2.创建socket
	SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);	//AF_INET表示通信协议类型为 TCP/IP-IPv4，SOCK_DGRAM指套接字类型为UDP用户数据报，IPPROTO_UDP保护方式。成功后返回套接字。
	if (SOCKET_ERROR == client_socket) {
		printf("创建socket失败！\n");
		WSACleanup();
		return -2;
	}
	else printf("创建socket成功！\n");

	//3.获取服务器协议地址组，
	SOCKADDR_IN server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(53);
	server_addr.sin_addr.S_un.S_addr = inet_addr(root_IP);

	int server_addr_length = sizeof(server_addr);

	//调试所用
	//memset(send_message, 0, sizeof(send_message));
	//strcpy(send_message, "实验数据来自client\n");

	//4.发送数据
	int real_send_length = sendto(client_socket, send_message1, send_length1, 0, (sockaddr *)&server_addr, server_addr_length);
	if (real_send_length == -1)
	{
		printf("发送失败\n");
		closesocket(client_socket);
		WSACleanup();
		return -3;
	}
	else printf("成功发送 %d 个字节！\n", real_send_length);

	//5.接收数据
	int receive_length = recvfrom(client_socket, receive_message1, BUF_SIZE, 0, (sockaddr *)&server_addr, &server_addr_length);

	if (receive_length < 0)
	{
		printf("接收失败\n");
		closesocket(client_socket);
		WSACleanup();
		return -4;
	}
	else printf("成功接收 %d 个字节\n", receive_length);

	//调试所用
	//strtobit(receive_message1);

	//6.解析响应的DNS数据报
	int flag = dealReceiveMessage(receive_message1, IP1, send_length1, receive_length);

	//7.关闭套接字
	closesocket(client_socket);
	WSACleanup();

	return flag;
}

//解析迭代查询时服务器返回的报文
int dealReceiveMessage(char* receive_message, char* IP, int send_length, int receive_length) {
	DNS_HEADER* header = (DNS_HEADER*)receive_message;
	int flag = 0;			//0 代表返回的是下一个要查询的服务器的IP地址，1代表是最终的查询结果
	if (header->answerRRs == 0){
		//选择第一个IP地址
		RR* resource = (RR*)(receive_message + send_length);
		short length = 0;
		while (ntohs(resource->query_type) != 1)
		{
			length = ntohs(resource->dataLength);
			//printf("%d\n", length);
			length = length + 12;
			resource = (RR*)((char*)resource +length);
		}
		IP[0] = resource->data[0];
		IP[1] = resource->data[1];
		IP[2] = resource->data[2];
		IP[3] = resource->data[3];

		/*选择最后一个IP地址；
		RR* resource = (RR*)(receive_message + receive_length-1);
		IP[0] = *(((char*)resource) - 3);
		IP[1] = *(((char*)resource) - 2);
		IP[2] = *(((char*)resource) - 1);
		IP[3] = *(char*)resource;
		*/
	}
	else {
		RR* resource = (RR*)(receive_message + send_length);
		if (ntohs(resource->query_type) == 1) {
			IP[0] = resource->data[0];
			IP[1] = resource->data[1];
			IP[2] = resource->data[2];
			IP[3] = resource->data[3];
			flag = 1;
			char temp[20];
			buildIP(IP, temp);
			printf("查询到IP地址为 %s\n", temp);
		}
		else {
			printf("返回数据不是IP地址，无法查询！\n");
			system("pause");
			exit(0);
		}
	}
	return flag;
}

//将整数形式的IP转为字符串形式的IP
int buildIP(char* integerIP, char* stringIP) {
	//strtobit(integerIP);
	int length = 0;
	for (int i = 0; i < 4; i++) {
		sprintf(stringIP + length, "%d", (unsigned char)integerIP[i]);
		length = strlen(stringIP);
		stringIP[length] = '.';
		length++;
	}
	stringIP[--length] = '\0';
	printf("%s\n", stringIP);
	return 0;
}