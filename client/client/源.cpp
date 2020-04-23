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

typedef struct dns_query_suffix 
{
	uint16_t query_type;	//查询类型
	uint16_t query_class;	//查询类
}DNS_QUERY_SUFFIX;

void split(char *src, const char *separator, char **dest, int *num);
char* stringName(char* DomainName);
int buildSendMessage(char* send_message, char* DomainName);
void strtobit(char *chr);
int Socket(char* send_message, int send_length, char* receive_message);
int buildIP(char* integerIP, char* stringIP);

int main()
{
	char send_message[BUF_SIZE];	//发送报文
	char receive_message[BUF_SIZE];	//接收报文
	char DomainName[256];			//存储域名
	printf("请输入要查询的域名：");
	scanf("%s", DomainName);
	
	int length = buildSendMessage(send_message, DomainName);
	Socket(send_message, length, receive_message);
	
	system("pause");
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

//生成问题Name字符串
char* stringName(char* DomainName) {
	int i = 0, num = 0;			//num表示分割后几级域名
	char *revbuf[4] = { 0 };	//存放分割后的各级域名
	split(DomainName, ".", revbuf, &num); 
								//调用函数进行分割 
										   
	//for (i = 0; i < num; i++)	//输出返回的每个内容
	//	printf("%s\n", revbuf[i]);

	int len = strlen(DomainName);
	char* name = (char*)malloc(500*sizeof(char));
	
	int p = 0;	//在name数组中填写域名的长度
	for (i = 0; i < num; i++) {
		name[p] = strlen(revbuf[i]);
		name[p + 1] = '\0';
		strcat(name, revbuf[i]);
		p = p + name[p] + 1;
	}
	name[p] = 0;
	return name;
}

//以二进制形式输出字符串。调试所用

///
void strtobit(char *chr)
{
	char *pchr = chr;
	int i, j;
	for (i = 0; i<100; i++)
	{
		printf("%d ", i + 1);
		for (j = 7; j >= 0; j--)
		{
			char tmpp = pchr[i];
			tmpp = pchr[i] & (1 << j);
			printf("%d", tmpp >> j);
		}
		printf("\n");
	}
}

//构建DNS报文
int buildSendMessage(char* send_message, char* DomainName) {
	DNS_HEADER* header = (DNS_HEADER*)send_message;
	memset(send_message, 0, BUF_SIZE);
	
	//填充首部(！！！！！！！！！！！！！！！！！！！！！！！！！！！关于位域 大小端问题！！！！！！)
	header->transactionID = htons(1);	//首部标识
	header->QR = 0;
	header->opcode = 0;
	header->AA = 0;
	header->TC = 0;
	header->RD = 1;		//表示期望递归。后面需要根据用户输入更改!!!!!!
	header->RA = 0;
	header->rcode = 0;
	header->questions = htons(1);

	//填充查询名

	
	char* temp = stringName(DomainName);		//查询名
	strcpy(send_message + sizeof(DNS_HEADER), temp);
	int name_length = strlen(temp);
	free(temp);
	temp = NULL;
	//填充查询类型和查询类
	DNS_QUERY_SUFFIX* suffix = (DNS_QUERY_SUFFIX*)(send_message + sizeof(DNS_HEADER) + name_length + 1);
	suffix->query_type = htons(1);
	suffix->query_class = htons(1);

//调试所用
//printf("\n这是查询报文：\n");
//strtobit(send_message);
	//计算报文长度
	return sizeof(DNS_HEADER) + name_length + 1 + sizeof(DNS_QUERY_SUFFIX);   //这里是获取结构体的大小和发送内容的大小之和
}

//发送接收DNS报文
int Socket(char* send_message, int send_length, char* receive_message) {

	//1.请求版本协议
	WORD socketVersion = MAKEWORD(2, 2);	//版本
	WSADATA wsaData;
	WSAStartup(socketVersion, &wsaData);
	if ( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("请求版本协议失败！\n");
		return -1;
	}
	else printf("请求版本协议成功！\n");

	//2.创建socket
	SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);	//AF_INET表示通信协议类型为 TCP/IP-IPv4，SOCK_DGRAM指套接字类型为
																//UDP用户数据报，IPPROTO_UDP保护方式。成功后返回套接字。
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
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");	//DNS服务器的地址：模拟的 127.0.0.1 或者真实的 192.168.1.1 
	//根域名服务器 192.36.148.17
	//得到 a.dns.cn [203.119.25.1]
	//dns.edu.cn [202.38.109.35]	
	//dns.nuaa.edu.cn [202.119.64.123]

	int server_addr_length = sizeof(server_addr);
	
//调试所用
//memset(send_message, 0, sizeof(send_message));
//strcpy(send_message, "实验数据来自client\n");

	//4.发送数据
	int real_send_length = sendto(client_socket, send_message, send_length, 0, (sockaddr *)&server_addr, server_addr_length);
	if (real_send_length  == -1)
	{
		printf("发送失败\n");
		closesocket(client_socket);
		WSACleanup();
		return -3;

	}
	else printf("成功发送 %d 个字节！\n", real_send_length);

	//5.接收数据
	int receive_length = recvfrom(client_socket, receive_message, BUF_SIZE, 0, (sockaddr *)&server_addr, &server_addr_length);
	
	if (receive_length < 0)
	{
		printf("接收失败\n");
		closesocket(client_socket);
		WSACleanup();
		return -4;
	}
	else printf("成功接收 %d 个字节\n", receive_length);
	
	//6.解析响应的DNS数据报
	//！！！！！！！！！！！！！！！！！！！！！！！！！！！！！解析DNS响应报文待完成
	DNS_HEADER* temp = (DNS_HEADER*)receive_message;
	//if (temp->answerRRs == 0)
	//{
	//	printf("ack error\n");
	//	return -5;
	//}
	//else 
	//printf("这是接收报文\n");
	//strtobit(receive_message);
	char IP[10];
	char stringIP[20];
	char * p = receive_message + receive_length - 4;
	IP[0] = *(char*)p;
	IP[1] = *(char*)(p + 1);
	IP[2] = *(char*)(p + 2);
	IP[3] = *(char*)(p + 3);
	buildIP(IP, stringIP);
	printf("查询IP地址为：%s", stringIP);
	closesocket(client_socket);
	WSACleanup();

	return 0;
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