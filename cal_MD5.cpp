#include "stdafx.h"
#include "cal_MD5.h"
#include <iostream>
#include <string>
#include <Windows.h>
#include "logger_record.h"
#include "tool_functions.h"
using namespace std;

/* Constants for MD5Transform routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions.
*/
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
*/
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
*/
#define FF(a, b, c, d, x, s, ac) { \
	(a) += F ((b), (c), (d)) + (x) + ac; \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
	(a) += G ((b), (c), (d)) + (x) + ac; \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
	(a) += H ((b), (c), (d)) + (x) + ac; \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
	(a) += I ((b), (c), (d)) + (x) + ac; \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}


const byte CalMD5::PADDING[64] = { 0x80 };
const char CalMD5::HEX[16] = {
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 'a', 'b',
	'c', 'd', 'e', 'f'
};

/* Default construct. */
CalMD5::CalMD5() {
	reset();
}

/* Construct a MD5 object with a input buffer. */
CalMD5::CalMD5(const void *input, size_t length) {
	reset();
	update(input, length);
}

/* Construct a MD5 object with a string. */
CalMD5::CalMD5(const string &str) {
	reset();
	update(str);
}

/* Construct a MD5 object with a file. */
CalMD5::CalMD5(ifstream &in) {
	reset();
	update(in);
}

/* Return the message-digest */
const byte* CalMD5::digest() {
	if (!_finished) {
		_finished = true;
		final();
	}
	return _digest;
}

/* Reset the calculate state */
void CalMD5::reset() {

	_finished = false;
	/* reset number of bits. */
	_count[0] = _count[1] = 0;
	/* Load magic initialization constants. */
	_state[0] = 0x67452301;
	_state[1] = 0xefcdab89;
	_state[2] = 0x98badcfe;
	_state[3] = 0x10325476;
}

/* Updating the context with a input buffer. */
void CalMD5::update(const void *input, size_t length) {
	update((const byte*)input, length);
}

/* Updating the context with a string. */
void CalMD5::update(const string &str) {
	update((const byte*)str.c_str(), str.length());
}

/* Updating the context with a file. */
void CalMD5::update(ifstream &in) {

	if (!in)
		return;

	std::streamsize length;
	char buffer[BUFFER_SIZE];
	while (!in.eof()) {
		in.read(buffer, BUFFER_SIZE);
		length = in.gcount();
		if (length > 0)
			update(buffer, length);
	}
	in.close();
}

void CalMD5::update(const byte *input, size_t length) {

	ulong i, index, partLen;

	_finished = false;

	/* Compute number of bytes mod 64 */
	index = (ulong)((_count[0] >> 3) & 0x3f);

	/* update number of bits */
	if ((_count[0] += ((ulong)length << 3)) < ((ulong)length << 3))
		_count[1]++;
	_count[1] += ((ulong)length >> 29);

	partLen = 64 - index;

	/* transform as many times as possible. */
	if (length >= partLen) {

		memcpy(&_buffer[index], input, partLen);
		transform(_buffer);

		for (i = partLen; i + 63 < length; i += 64)
			transform(&input[i]);
		index = 0;

	}
	else {
		i = 0;
	}

	/* Buffer remaining input */
	memcpy(&_buffer[index], &input[i], length - i);
}

void CalMD5::final() {

	byte bits[8];
	ulong oldState[4];
	ulong oldCount[2];
	ulong index, padLen;

	/* Save current state and count. */
	memcpy(oldState, _state, 16);
	memcpy(oldCount, _count, 8);

	/* Save number of bits */
	encode(_count, bits, 8);

	/* Pad out to 56 mod 64. */
	index = (ulong)((_count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	update(PADDING, padLen);

	/* Append length (before padding) */
	update(bits, 8);

	/* Store state in digest */
	encode(_state, _digest, 16);

	/* Restore current state and count. */
	memcpy(_state, oldState, 16);
	memcpy(_count, oldCount, 8);
}

/* MD5 basic transformation. Transforms _state based on block. */
void CalMD5::transform(const byte block[64]) {

	ulong a = _state[0], b = _state[1], c = _state[2], d = _state[3], x[16];

	decode(block, x, 64);

	/* Round 1 */
	FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

	_state[0] += a;
	_state[1] += b;
	_state[2] += c;
	_state[3] += d;
}

/* Encodes input (ulong) into output (byte). Assumes length is
a multiple of 4.
*/
void CalMD5::encode(const ulong *input, byte *output, size_t length) {

	for (size_t i = 0, j = 0; j < length; i++, j += 4) {
		output[j] = (byte)(input[i] & 0xff);
		output[j + 1] = (byte)((input[i] >> 8) & 0xff);
		output[j + 2] = (byte)((input[i] >> 16) & 0xff);
		output[j + 3] = (byte)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (byte) into output (ulong). Assumes length is
a multiple of 4.
*/
void CalMD5::decode(const byte *input, ulong *output, size_t length) {

	for (size_t i = 0, j = 0; j < length; i++, j += 4) {
		output[i] = ((ulong)input[j]) | (((ulong)input[j + 1]) << 8) |
			(((ulong)input[j + 2]) << 16) | (((ulong)input[j + 3]) << 24);
	}
}

/* Convert byte array to hex string. */
string CalMD5::bytesToHexString(const byte *input, size_t length) {
	string str = "", temp_str = "";
	str.reserve(length << 1);
	for (size_t i = 0; i < length; i++) {
		int t = input[i];
		int a = t / 16;
		int b = t % 16;
		str.append(1, HEX[a]);
		str.append(1, HEX[b]);
	}

	for (int i = 0; i != str.size(); i++)
	{
		temp_str += ::toupper(str[i]);
	}

	return temp_str;
}

/* Convert digest to string value */
string CalMD5::toString() {
	return bytesToHexString(digest(), 16);
}

std::string CalMD5::Calculate(wchar_t* FileDirectory)
{
	ifstream in(FileDirectory, ios::binary);
    if (!in)      
    {
        LoggerRecord::WriteLog(L"CalMD5::Calculate open file failed: " + to_wstring(GetLastError()), LogLevel::DEBUG);
        return "";
    }
		

	CalMD5 md5;
	std::streamsize length;
	char buffer[1024];
	while (!in.eof()) {
		in.read(buffer, 1024);
		length = in.gcount();
		if (length > 0)
			md5.update(buffer, length);
	}
	in.close();
	return md5.toString();
}


/*
	转换成16进制

void HexToAscii(unsigned char * pHex, unsigned char * pAscii, int nLen)
{
	unsigned char Nibble[2];

	for (int i = 0; i < nLen; i++)
	{
		Nibble[0] = (pHex[i] & 0xF0) >> 4;
		Nibble[1] = pHex[i] & 0x0F;
		for (int j = 0; j < 2; j++)
		{
			if (Nibble[j] < 10)
				Nibble[j] += 0x30;
			else
			{
				if (Nibble[j] < 16)
					Nibble[j] = Nibble[j] - 10 + 'A';
			}
			*pAscii++ = Nibble[j];
		}   // for (int j = ...)
	}   // for (int i = ...)
}

/*
absolute_path_： 被求md5的文件绝对路径

std::string CalMD5::Calculate(wchar_t* FileDirectory)
{
	wstring temp = FileDirectory;
	string strlog;
	string ret;
	DWORD lpReadNumberOfBytes;
	BYTE *pbHash;
	DWORD dwHashLen;
	DWORD dwFileSize;
	BOOL Result = TRUE;

	unsigned char* tmp = NULL;
	byte* lpReadFileBuffer = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTPROV hHash = NULL;
	//string temp1 = ToolFunctions::WStringToString(temp);
	//TRACE_INFO(EMINFO, ToolFunctions::WStringToString(temp));
	
	HANDLE hFile = CreateFileW(FileDirectory, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)                                        //如果CreateFile调用失败
	{
		//strlog = "CreateFile go wrong :" + GetError();
		LoggerRecord::WriteLog(L"CalMD5::Calculate CreateFile faild :" + std::to_wstring(GetLastError()), LogLevel::ERR);
		//Mangerment::log_file << "CreateFile go wrong :" << GetError() << endl;                //提示CreateFile调用失败，并输出错误号。visual studio中可在“工具”>“错误查找”中利用错误号得到错误信息。
		return "";
	}
	
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE)       //获得CSP中一个密钥容器的句柄
	{
		//Mangerment::log_file << "CryptAcquireContext go wrong:" << GetError() << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate CryptAcquireContext faild : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}
	
	if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash) == FALSE)     //初始化对数据流的hash，创建并返回一个与CSP的hash对象相关的句柄。这个句柄接下来将被CryptHashData调用。
	{
		//Mangerment::log_file << "CryptCreateHash go wrong:" << GetError() << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate CryptCreateHash faild : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}

	dwFileSize = GetFileSize(hFile, 0);    //获取文件的大小
	if (dwFileSize == 0xFFFFFFFF)               //如果获取文件大小失败
	{
		//Mangerment::log_file << "GetFileSize go wrong:" << GetError() << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate GetFileSize faild : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}

	lpReadFileBuffer = new byte[dwFileSize];
	
	if (ReadFile(hFile, lpReadFileBuffer, dwFileSize, &lpReadNumberOfBytes, NULL) == 0)        //读取文件
	{
		//Mangerment::log_file << "ReadFile go wrong:" << GetError() << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate ReadFile faild : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}
	if (CryptHashData(hHash, lpReadFileBuffer, lpReadNumberOfBytes, 0) == FALSE)      //hash文件
	{
		//Mangerment::log_file << "CryptHashData go wrong:" << GetError() << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate CryptHashData faild : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}

	dwHashLen = sizeof(DWORD);
	//以下注释掉的代码不用使用，因为已经知道md5值就占32个字节，没有必要通过CryptGetHashParam函数来得到字节数。
	/*
	BYTE *pbHashSize;
	if (!(pbHashSize=(byte*)malloc(dwHashLen)))      //为pbHashSize分配内存
	{
	cout<<"memory allocation failed:"<<GetError()<<endl;
	}
	//将第二个参数的值设为HP_HASHSIZE。dwHashLen中存放着hash值的字节数。这个调用必须在将第三个参数设置为HP_HASHVAL的调用前，这样才能分配正确数量的内存。
	if (CryptGetHashParam(hHash,HP_HASHSIZE,pbHashSize,&dwHashLen,0))
	{
	free(pbHashSize);
	}
	else
	{
	cout<<"get size go wrong"<<GetError()<<endl;
	}
	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwHashLen, 0))      //参照msdn       
	{
		//Mangerment::log_file << "get length wrong" << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate get length faild : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}
	pbHash = (byte*)malloc(dwHashLen);
	if (pbHash == NULL)
	{
		//Mangerment::log_file << "allocation failed" << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate malloc failed : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}
	memset(pbHash, 0, dwHashLen);
	if (CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0))            //获得md5值
	{
		tmp = (unsigned char *)malloc(sizeof(char) * 33);
		if (tmp)
		{
			memset(tmp, 0, sizeof(char) * 33);
			tmp[0x10] = 0;
			HexToAscii(pbHash, tmp, dwHashLen);
		}		
	}
	
	//modify by  jiehao.meng 使用未初始化的内存“tmp” 2018/12/07
	if (tmp)
	{
		ret = (char*)tmp;
		free(tmp);
		tmp = NULL;
	}	
	//善后工作
	if (CryptDestroyHash(hHash) == FALSE)          //销毁hash对象
	{
		//Mangerment::log_file << "CryptDestroyHash go wrong:" << GetError() << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate CryptDestroyHash failed : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}
	if (CryptReleaseContext(hProv, 0) == FALSE)
	{
		//Mangerment::log_file << "CryptReleaseContext go wrong:" << GetError() << endl;
		LoggerRecord::WriteLog(L"CalMD5::Calculate CryptReleaseContext failed : " + std::to_wstring(GetLastError()), LogLevel::ERR);
		Result = FALSE;
		goto clean_up;
	}

clean_up:
	if (lpReadFileBuffer)
	{
		delete[] lpReadFileBuffer;
	}
	if (hFile)
	{
		CloseHandle(hFile);
	}
	if (pbHash)
	{
		free(pbHash);
		pbHash = NULL;
	}
	if (!Result)
	{
		LoggerRecord::WriteLog(L"CalMD5::Calculate MD5 calc faild !", LogLevel::ERR);
		return "";
	}
	
	LoggerRecord::WriteLog(L"CalMD5::Calculate MD5 calc done: " + ToolFunctions::StringToWString(ret), LogLevel::INFO);
	return ret;
}
*/