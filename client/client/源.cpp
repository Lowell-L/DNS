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

typedef struct dns_query_suffix 
{
	uint16_t query_type;	//��ѯ����
	uint16_t query_class;	//��ѯ��
}DNS_QUERY_SUFFIX;

void split(char *src, const char *separator, char **dest, int *num);
char* stringName(char* DomainName);
int buildSendMessage(char* send_message, char* DomainName);
void strtobit(char *chr);
int Socket(char* send_message, int send_length, char* receive_message);
int buildIP(char* integerIP, char* stringIP);

int main()
{
	char send_message[BUF_SIZE];	//���ͱ���
	char receive_message[BUF_SIZE];	//���ձ���
	char DomainName[256];			//�洢����
	printf("������Ҫ��ѯ��������");
	scanf("%s", DomainName);
	
	int length = buildSendMessage(send_message, DomainName);
	Socket(send_message, length, receive_message);
	
	system("pause");
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

//��������Name�ַ���
char* stringName(char* DomainName) {
	int i = 0, num = 0;			//num��ʾ�ָ�󼸼�����
	char *revbuf[4] = { 0 };	//��ŷָ��ĸ�������
	split(DomainName, ".", revbuf, &num); 
								//���ú������зָ� 
										   
	//for (i = 0; i < num; i++)	//������ص�ÿ������
	//	printf("%s\n", revbuf[i]);

	int len = strlen(DomainName);
	char* name = (char*)malloc(500*sizeof(char));
	
	int p = 0;	//��name��������д�����ĳ���
	for (i = 0; i < num; i++) {
		name[p] = strlen(revbuf[i]);
		name[p + 1] = '\0';
		strcat(name, revbuf[i]);
		p = p + name[p] + 1;
	}
	name[p] = 0;
	return name;
}

//�Զ�������ʽ����ַ�������������

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

//����DNS����
int buildSendMessage(char* send_message, char* DomainName) {
	DNS_HEADER* header = (DNS_HEADER*)send_message;
	memset(send_message, 0, BUF_SIZE);
	
	//����ײ�(����������������������������������������������������������λ�� ��С�����⣡����������)
	header->transactionID = htons(1);	//�ײ���ʶ
	header->QR = 0;
	header->opcode = 0;
	header->AA = 0;
	header->TC = 0;
	header->RD = 1;		//��ʾ�����ݹ顣������Ҫ�����û��������!!!!!!
	header->RA = 0;
	header->rcode = 0;
	header->questions = htons(1);

	//����ѯ��

	
	char* temp = stringName(DomainName);		//��ѯ��
	strcpy(send_message + sizeof(DNS_HEADER), temp);
	int name_length = strlen(temp);
	free(temp);
	temp = NULL;
	//����ѯ���ͺͲ�ѯ��
	DNS_QUERY_SUFFIX* suffix = (DNS_QUERY_SUFFIX*)(send_message + sizeof(DNS_HEADER) + name_length + 1);
	suffix->query_type = htons(1);
	suffix->query_class = htons(1);

//��������
//printf("\n���ǲ�ѯ���ģ�\n");
//strtobit(send_message);
	//���㱨�ĳ���
	return sizeof(DNS_HEADER) + name_length + 1 + sizeof(DNS_QUERY_SUFFIX);   //�����ǻ�ȡ�ṹ��Ĵ�С�ͷ������ݵĴ�С֮��
}

//���ͽ���DNS����
int Socket(char* send_message, int send_length, char* receive_message) {

	//1.����汾Э��
	WORD socketVersion = MAKEWORD(2, 2);	//�汾
	WSADATA wsaData;
	WSAStartup(socketVersion, &wsaData);
	if ( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("����汾Э��ʧ�ܣ�\n");
		return -1;
	}
	else printf("����汾Э��ɹ���\n");

	//2.����socket
	SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);	//AF_INET��ʾͨ��Э������Ϊ TCP/IP-IPv4��SOCK_DGRAMָ�׽�������Ϊ
																//UDP�û����ݱ���IPPROTO_UDP������ʽ���ɹ��󷵻��׽��֡�
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
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");	//DNS�������ĵ�ַ��ģ��� 127.0.0.1 ������ʵ�� 192.168.1.1 
	//������������ 192.36.148.17
	//�õ� a.dns.cn [203.119.25.1]
	//dns.edu.cn [202.38.109.35]	
	//dns.nuaa.edu.cn [202.119.64.123]

	int server_addr_length = sizeof(server_addr);
	
//��������
//memset(send_message, 0, sizeof(send_message));
//strcpy(send_message, "ʵ����������client\n");

	//4.��������
	int real_send_length = sendto(client_socket, send_message, send_length, 0, (sockaddr *)&server_addr, server_addr_length);
	if (real_send_length  == -1)
	{
		printf("����ʧ��\n");
		closesocket(client_socket);
		WSACleanup();
		return -3;

	}
	else printf("�ɹ����� %d ���ֽڣ�\n", real_send_length);

	//5.��������
	int receive_length = recvfrom(client_socket, receive_message, BUF_SIZE, 0, (sockaddr *)&server_addr, &server_addr_length);
	
	if (receive_length < 0)
	{
		printf("����ʧ��\n");
		closesocket(client_socket);
		WSACleanup();
		return -4;
	}
	else printf("�ɹ����� %d ���ֽ�\n", receive_length);
	
	//6.������Ӧ��DNS���ݱ�
	//��������������������������������������������������������������DNS��Ӧ���Ĵ����
	DNS_HEADER* temp = (DNS_HEADER*)receive_message;
	//if (temp->answerRRs == 0)
	//{
	//	printf("ack error\n");
	//	return -5;
	//}
	//else 
	//printf("���ǽ��ձ���\n");
	//strtobit(receive_message);
	char IP[10];
	char stringIP[20];
	char * p = receive_message + receive_length - 4;
	IP[0] = *(char*)p;
	IP[1] = *(char*)(p + 1);
	IP[2] = *(char*)(p + 2);
	IP[3] = *(char*)(p + 3);
	buildIP(IP, stringIP);
	printf("��ѯIP��ַΪ��%s", stringIP);
	closesocket(client_socket);
	WSACleanup();

	return 0;
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