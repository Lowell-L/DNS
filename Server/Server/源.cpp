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
	uint16_t transactionID;	//�Ự��ʶ
	
	//Flags
	uint8_t RD : 1;		//��ʾ�����ݹ�
	uint8_t TC : 1;		//��ʾ�ɽضϵ�
	uint8_t AA : 1;		//��ʾ��Ȩ�ش�
	uint8_t opcode : 4;	//0��ʾ��׼��ѯ��1��ʾ�����ѯ��2��ʾ������״̬����
	uint8_t QR : 1;		//��ѯ/��Ӧ��־��0Ϊ��ѯ��1Ϊ��Ӧ
	uint8_t rcode : 4;	//��ʾ�����룬0��ʾû�в��3��ʾ���ֲ��2��ʾ����������
	uint8_t: 3;
	uint8_t RA : 1;		//��ʾ���õݹ�

	uint16_t questions;	//������
	uint16_t answerRRs;	//
	uint16_t authorityRRs;
	uint16_t additionalRRs;
} DNS_HEADER;

#pragma pack(push, 1)//�������״̬���趨Ϊ1�ֽڶ���(TTLԪ�� 4�ֽڶ����������)
/*
typedef struct dns_answers
{
	uint16_t name;			//������ƫ��ָ�� 0xC00C��
	uint16_t query_type;	//��ѯ����
	uint16_t query_class;	//��ѯ��
	uint32_t TTL;			//Time to live
	uint16_t dataLength;	//��Դ���ݳ���
	//4�ֽڶ������⣡��������������������������
	
	//��Դ���ݣ�IP��ַ��
	uint8_t data1;
	uint8_t data2;
	uint8_t data3;
	uint8_t data4;

}DNS_ANSWERS;
*/
typedef struct resource_Record
{
	uint16_t name;			//������ƫ��ָ�� 0xC00C��
	uint16_t query_type;	//��ѯ����
	uint16_t query_class;	//��ѯ��
	uint32_t TTL;			//Time to live
	uint16_t dataLength;	//��Դ���ݳ���
	uint8_t data[];			//��Դ����
}RR;
#pragma pack(pop) //�ָ�����״̬

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
	//1.����汾Э��
	WORD socketVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	WSAStartup(socketVersion, &wsaData);
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		printf("����Э��汾ʧ�ܣ�\n");
		return -1;
	}
	else printf("����Э��汾�ɹ���\n");

	//2.����socket
	SOCKET server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (server_socket == SOCKET_ERROR) {
		printf("����socketʧ�ܣ�\n");
		WSACleanup();
		return -2;
	}
	else printf("����socket�ɹ���\n");

	//3.����Э���ַ�壺IP��ַ���˿�
	SOCKADDR_IN server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;			//Э��汾
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(53);

	//4.��
	if (-1 == bind(server_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) ){
		printf("��ʧ�ܣ�\n");
		closesocket(server_socket);
		WSACleanup();
		return -3;
	}
	else printf("�󶨳ɹ���\n");

	//5. ���ͽ���
	SOCKADDR_IN client_addr;
	int client_addr_length = sizeof(client_addr);
	
	char receive_message[BUF_SIZE];
	char send_message[BUF_SIZE];

	while (true) {
		printf("\n�ȴ��û����ӡ���\n");

		//��������
		int receive_length = recvfrom(server_socket, receive_message, BUF_SIZE, 0, (sockaddr*)&client_addr, &client_addr_length);
		if (receive_length == -1) {
			printf("����ʧ�ܣ�\n");
			break;
		}
		else printf("���յ� %d ���ֽڣ�\n", receive_length);
		
//��������
//memset(send_message, 0, BUF_SIZE);
//strcpy(send_message, "һ�����Է���˵�UDP���ݰ�\n\0");

		//����DSN���ģ���ѯ�������д�뷢�ͱ���send_message��
		int send_length = DNS(receive_message, send_message, receive_length);

		//��������
		int real_send_length = sendto(server_socket, send_message, send_length, 0, (sockaddr *)&client_addr, client_addr_length);
		if (real_send_length == -1) {
			printf("����ʧ�ܣ�\n");
			return -4;
		}
		else printf("�ɹ����� %d ���ֽڣ�\n", real_send_length);
	}

	//6.�ر��׽���
	closesocket(server_socket);
	WSACleanup();
	
	system("pause");
	return 0;
}

/*
 * ���ܣ�    ģ��DNS
 * ���������receive_message	������
 *			 send_message		��Ӧ����
 *			 receive_length		�����ĳ���
 * ����ֵ��  ����(int)			��ʾ��������Ӧ���ĵĳ���
 * ��飺	 ���ȸ��ݺ��� buildDomainName ������յ���DNS���ģ����еõ����ʮ������ʽ�������ַ�����
 *			 Ȼ����ú��� localFind �ڱ��ز��Ҵ�������Ӧ��IP��ַ��
 *			 ����ҵ�������ú��� buildSendMessage �������ͱ��ģ�
 *			 ����Ҳ���
*/
int DNS(char *receive_message, char* send_message, int receive_length){
	char DomainName[256];								//�洢����
	char IP[50];										//�洢IP��ַ������
	buildDomainName(receive_message+12, DomainName);		//��ȡ����
	int send_length = 0;								//��Ӧ���ĳ��ȣ�

	//���ز�ѯ�ҵ���������Ӧ����
	if (localFind(DomainName, IP) == 1) {
		send_length = buildSendMessage(receive_message, send_message, IP, receive_length);
	}

	//���ز�ѯ����
	else {
		printf("����δ��ѯ����\n");

		char root_IP[50];
		printf("�������������������IP��ַ��\n");
		scanf("%s", root_IP);

		char receive_message1[BUF_SIZE];
		char send_message1[BUF_SIZE];
		char IP1[50];
		int send_length1 = receive_length;		//���Ʒ��ͳ���
		for (int i = 0; i < send_length1; i++)	//���Ʒ��ͱ���
			send_message1[i] = receive_message[i];
		//��������
		//strtobit(receive_message);
		//strtobit(send_message1);
		if (((DNS_HEADER*)send_message1)->RD == 1) {
			//���ϲ�ѯ
			while (true) {
				int flag = onlineFind(root_IP, send_message1, receive_message1, send_length1, IP1);
				if (flag < 0) {
					printf("��ѯʧ��\n");
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
			//������ѯ
			while (true) {
				int flag = onlineFind(root_IP, send_message1, receive_message1, send_length1, IP1);
				if (flag < 0) {
					printf("��ѯʧ��\n");
					system("pause");
					exit(0);
				}
				else if (flag == 0) {
					memset(root_IP, 0, 50);
					buildIP(IP1, root_IP);
					printf("�����������һ�������� %s ��ѯ\n", root_IP);
					getchar(); getchar();
					continue;
				}
				else if (flag == 1) {
					break;
				}
			}
			send_length = buildSendMessage(receive_message, send_message, IP1, receive_length);
		}

		//�����߲�ѯ����IP��ַ�洢���ļ��У�
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

//��������
//strtobit(send_message);
	return send_length;
}

/*
 * ���ܣ������������е��������������ַ���
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
	printf("�õ�������%s\n", DomainName);
	return 0;
}
	
//�и��ַ���
void split(char *src, const char *separator, char **dest, int *num) {
	/*
	src Դ�ַ������׵�ַ(buf�ĵ�ַ)
	separator ָ���ķָ��ַ�
	dest �������ַ���������
	num �ָ�����ַ����ĸ���
	*/
	char *pNext;
	int count = 0;
	if (src == NULL || strlen(src) == 0) //�������ĵ�ַΪ�ջ򳤶�Ϊ0��ֱ����ֹ 
		return;
	if (separator == NULL || strlen(separator) == 0) //��δָ���ָ���ַ�����ֱ����ֹ 
		return;
	pNext = (char *)strtok(src, separator); //����ʹ��(char *)����ǿ������ת��(��Ȼ��д�еı������в������ָ�����)
	while (pNext != NULL) {
		*dest++ = pNext;
		++count;
		pNext = (char *)strtok(NULL, separator);  //����ʹ��(char *)����ǿ������ת��
	}
	*num = count;
}

//���ز�ѯ
int localFind(char * DomainName, char* IP) {
	int flag = 0;		//��־�Ƿ��ѯ�� 0Ϊδ��ѯ����1Ϊ��ѯ��
	//���ļ�
	FILE * fp;
	if ((fp = fopen("localAddress.txt", "a+")) == NULL) {
		printf("cannot open this file!\n");
		system("pause");
		exit(0);
	}

	char temp[300];		//����ļ���һ��
	int num = 0;		//��ŷָ���ַ����ĸ���
	char *revbuf[5] = { 0 };	//��ŷָ��ĸ�����
	
	while (fgets(temp, 300, fp) != NULL) {
		//���ú������зָ� 
		//split(temp, " ", revbuf, &num);
		//printf("%d\n", num);
		//for (int i = 0; i < num; i++)	//������ص�ÿ������
		//	printf("%s\n", revbuf[i]);
		if (strcmp(DomainName, strtok(temp, " ")) == 0) {
			flag = 1;	//�ҵ�
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

//��ѯ��IP��ַ��������Ӧ����
int buildSendMessage(char* receive_message, char* send_message, char* IP, int receive_length) {
	//����ѯ���ĸ��Ƶ���Ӧ������
	for (int i = 0; i < receive_length; i++)
		send_message[i] = receive_message[i];
	
	DNS_HEADER* header = (DNS_HEADER*)send_message;
	header->QR = 1;		//1��ʾ��Ӧ
	header->answerRRs = htons(1);

	RR* answers = (RR*)(send_message + receive_length);
	answers->name = htons(0xc00c);		//������ƫ��ָ�� 0xC00C��32 33
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

//�Զ�������ʽ����ַ�������������
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

//��Ŀ���������ѯ
int onlineFind(char* root_IP, char* send_message1, char* receive_message1,int send_length1, char* IP1) {
	printf("\n��ʼ���ӷ����� %s\n", root_IP);

	//1.����汾Э��
	WORD socketVersion = MAKEWORD(2, 2);	//�汾
	WSADATA wsaData;
	WSAStartup(socketVersion, &wsaData);
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("����汾Э��ʧ�ܣ�\n");
		return -1;
	}
	else printf("����汾Э��ɹ���\n");

	//2.����socket
	SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);	//AF_INET��ʾͨ��Э������Ϊ TCP/IP-IPv4��SOCK_DGRAMָ�׽�������ΪUDP�û����ݱ���IPPROTO_UDP������ʽ���ɹ��󷵻��׽��֡�
	if (SOCKET_ERROR == client_socket) {
		printf("����socketʧ�ܣ�\n");
		WSACleanup();
		return -2;
	}
	else printf("����socket�ɹ���\n");

	//3.��ȡ������Э���ַ�飬
	SOCKADDR_IN server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(53);
	server_addr.sin_addr.S_un.S_addr = inet_addr(root_IP);

	int server_addr_length = sizeof(server_addr);

	//��������
	//memset(send_message, 0, sizeof(send_message));
	//strcpy(send_message, "ʵ����������client\n");

	//4.��������
	int real_send_length = sendto(client_socket, send_message1, send_length1, 0, (sockaddr *)&server_addr, server_addr_length);
	if (real_send_length == -1)
	{
		printf("����ʧ��\n");
		closesocket(client_socket);
		WSACleanup();
		return -3;
	}
	else printf("�ɹ����� %d ���ֽڣ�\n", real_send_length);

	//5.��������
	int receive_length = recvfrom(client_socket, receive_message1, BUF_SIZE, 0, (sockaddr *)&server_addr, &server_addr_length);

	if (receive_length < 0)
	{
		printf("����ʧ��\n");
		closesocket(client_socket);
		WSACleanup();
		return -4;
	}
	else printf("�ɹ����� %d ���ֽ�\n", receive_length);

	//��������
	//strtobit(receive_message1);

	//6.������Ӧ��DNS���ݱ�
	int flag = dealReceiveMessage(receive_message1, IP1, send_length1, receive_length);

	//7.�ر��׽���
	closesocket(client_socket);
	WSACleanup();

	return flag;
}

//����������ѯʱ���������صı���
int dealReceiveMessage(char* receive_message, char* IP, int send_length, int receive_length) {
	DNS_HEADER* header = (DNS_HEADER*)receive_message;
	int flag = 0;			//0 �����ص�����һ��Ҫ��ѯ�ķ�������IP��ַ��1���������յĲ�ѯ���
	if (header->answerRRs == 0){
		//ѡ���һ��IP��ַ
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

		/*ѡ�����һ��IP��ַ��
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
			printf("��ѯ��IP��ַΪ %s\n", temp);
		}
		else {
			printf("�������ݲ���IP��ַ���޷���ѯ��\n");
			system("pause");
			exit(0);
		}
	}
	return flag;
}

//��������ʽ��IPתΪ�ַ�����ʽ��IP
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