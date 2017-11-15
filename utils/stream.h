#include <string>
#include <vector>
#include <stdlib.h>
#include <unistd.h>

using namespace std;

enum StreamDataType
{
	INTEGER,
	STRING
};

struct StreamBuf
{
	int dataType;
	int dataLen;
	int theData;
	std::string stringData;
	StreamBuf();
	~StreamBuf();
};

class MyByteStream
{
	private:
		std::vector<uint8_t> _stream;
		void Clear();
		void IntegerAppend(int num);
		void StringAppend(std::string &str);

	public:
		virtual ~MyByteStream();
		MyByteStream();
		MyByteStream(const MyByteStream &s);
		MyByteStream &operator=(const MyByteStream &s);
		MyByteStream(uint8_t *buf, int len);
		int Int2Stream(int num);
		int String2Stream(std::string &str);
		int CString2Stream(char *str);
		void Export(uint8_t *buf, int sz);
		int Length();
		void Clear(std::vector<StreamBuf> &data);
		void Get(std::vector<StreamBuf> &data);
};

