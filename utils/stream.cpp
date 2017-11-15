#include <string>
#include <vector>

using namespace std;

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>

#include "stream.h"

StreamBuf::StreamBuf()
{
	dataType = -1;
	dataLen = 0;
	theData = 0;
	stringData = "";
}

StreamBuf::~StreamBuf() { }

MyByteStream::~MyByteStream()
{
	Clear();
}

MyByteStream::MyByteStream()
{
}

MyByteStream::MyByteStream(const MyByteStream &s)
{
	Clear();
	for (int i = 0; i < s._stream.size(); i++)
		_stream.push_back(s._stream[i]);
}

MyByteStream::MyByteStream(uint8_t *buf, int len)
{
	Clear();
	for (int i = 0; i < len; i++)
		_stream.push_back(buf[i]);
}

MyByteStream& MyByteStream::operator=(const MyByteStream &s)
{
	Clear();
	for (int i = 0; i < s._stream.size(); i++)
		_stream.push_back(s._stream[i]);
	return *this;
}

void MyByteStream::Clear()
{
	while (_stream.size())
		_stream.erase(_stream.begin());
}

void MyByteStream::IntegerAppend(int num)
{
	int tw = htonl(num);
	uint8_t buf[sizeof(int)];
	memcpy(buf, &tw, sizeof(int));
	for (int i = 0; i < sizeof(int); i++)
		_stream.push_back(buf[i]);
}

void MyByteStream::StringAppend(std::string &str)
{
	for (int i = 0; i < str.length(); i++)
		_stream.push_back(str[i]);
}

int MyByteStream::Int2Stream(int num)
{
	uint8_t type;

	type = (uint8_t)INTEGER;
	_stream.push_back(type);
	IntegerAppend(num);

	return (int)_stream.size();
}

int MyByteStream::String2Stream(std::string &str)
{
	uint8_t type;

	type = (uint8_t)STRING;
	_stream.push_back(type);

	IntegerAppend((int)str.length());
	StringAppend(str);

	return (int)_stream.size();
}

int MyByteStream::CString2Stream(char *str)
{
	std::string data = str;
	return String2Stream(data);
}


void MyByteStream::Clear(std::vector<StreamBuf> &data)
{
	while (data.size())
		data.erase(data.begin());
}

void MyByteStream::Get(std::vector<StreamBuf> &data)
{
	uint8_t dataType;
	int intData;
	uint8_t *tbuf;
	uint8_t ibuf[sizeof(int)];

	for (int i = 0; i < _stream.size();) 
	{
		StreamBuf s;

		dataType = _stream[i++];
		s.dataType = dataType;

		switch (dataType)
		{
			case INTEGER:
				s.dataLen = sizeof(int);
				for (int j = i, k = 0; k < sizeof(int); j++)
					ibuf[k++] = _stream[i++];
				memcpy(&intData, ibuf, sizeof(intData));
				s.theData = ntohl(intData);
				data.push_back(s);
				break;

			case STRING:
				for (int j = i, k = 0; k < sizeof(int); j++)
					ibuf[k++] = _stream[i++];
				memcpy(&intData, ibuf, sizeof(intData));
				s.dataLen = ntohl(intData);
				tbuf = new uint8_t[s.dataLen+1];
				for (int j = i, k = 0; k < s.dataLen; j++)
					tbuf[k++] = _stream[i++];
				tbuf[s.dataLen] = 0;
				s.stringData = (char *)tbuf;
				data.push_back(s);
				delete tbuf;
				break;
		}
	}
}

void MyByteStream::Export(uint8_t *buf, int sz)
{
	int rsz;

	if (sz >= _stream.size())
		rsz = (int)_stream.size();
	else
		rsz = sz;

	for (int i = 0; i < rsz; i++)
		buf[i] = _stream[i];
}

int MyByteStream::Length()
{
	return (int)_stream.size();
}
