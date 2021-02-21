#include <stdio.h>
#include <string.h>
#include <windows.h>

const int thread_count = 2;
HANDLE th[2];
DWORD tid[2];
const char *thread_messages[2] = {
	"First thread executing",
	"Second thread executing"
};

DWORD __stdcall doSomething(void *arg)
{
	DWORD id = GetCurrentThreadId();
	int num = -1;

	for (int i = 0 ; i < thread_count ; ++i)
	{
		if (id == tid[i])
		{
			num = i + 1;
			if (num == 2) printf("[%02d] %s\n", num, thread_messages[i]);
			break;
		}
	}

	for (unsigned int i = 0 ; i < 0x10000 ; ++i);
	if (num == 2) printf("[%02d] Thread done.\n", num);

	return 0;
}

int main(int argc, char const *argv[])
{
	int err;

	for (int i = 0 ; i < thread_count ; ++i)
	{
		//printf("[00] Thread %d starting\n", i + 1);
		th[i] = CreateThread(NULL, 0, doSomething, NULL, 0, tid+i);
		if (!th[i])
		{
			printf("[00] Couldn't create thread %d: %d\n", i + 1, GetLastError());
		}
		for (unsigned int i = 0 ; i < 0x1000 ; ++i);
	}

	//printf("[00] Waiting for all threads to end...\n");
	for (int i = 0 ; i < thread_count ; ++i)
		WaitForSingleObject(th[i], INFINITE);
	printf("\n[00] Done.\n");

	return 0;
}
