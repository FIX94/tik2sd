/*
 * Copyright (C) 2016 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdio.h>
#include <vector>
#include <set>
#include <string>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/sys_functions.h"
#include "dynamic_libs/vpad_functions.h"
#include "system/memory.h"
#include "common/common.h"
#include "main.h"
#include "exploit.h"
#include "iosuhax.h"

static const char *sdCardVolPath = "/vol/storage_sdcard";
static const char *tikPath = "/vol/system/rights/ticket/apps";
static const char *oddTikVolPath = "/vol/storage_odd_tickets";
//just to be able to call async
void someFunc(void *arg)
{
	(void)arg;
}

static int mcp_hook_fd = -1;
int MCPHookOpen()
{
	//take over mcp thread
	mcp_hook_fd = MCP_Open();
	if(mcp_hook_fd < 0)
		return -1;
	IOS_IoctlAsync(mcp_hook_fd, 0x62, (void*)0, 0, (void*)0, 0, (void*)someFunc, (void*)0);
	//let wupserver start up
	sleep(1);
	if(IOSUHAX_Open("/dev/mcp") < 0)
		return -1;
	return 0;
}

void MCPHookClose()
{
	if(mcp_hook_fd < 0)
		return;
	//close down wupserver, return control to mcp
	IOSUHAX_Close();
	//wait for mcp to return
	sleep(1);
	MCP_Close(mcp_hook_fd);
	mcp_hook_fd = -1;
}

void println(int line, const char *msg)
{
	int i;
	for(i = 0; i < 2; i++)
	{	//double-buffered font write
		OSScreenPutFontEx(0,0,line,msg);
		OSScreenPutFontEx(1,0,line,msg);
		OSScreenFlipBuffersEx(0);
		OSScreenFlipBuffersEx(1);
	}
}

int fsa_read(int fsa_fd, int fd, void *buf, int len)
{
	int done = 0;
	uint8_t *buf_u8 = (uint8_t*)buf;
	while(done < len)
	{
		size_t read_size = len - done;
		int result = IOSUHAX_FSA_ReadFile(fsa_fd, buf_u8 + done, 0x01, read_size, fd, 0);
		if(result < 0)
			return result;
		else
			done += result;
	}
	return done;
}

int fsa_write(int fsa_fd, int fd, const void *buf, int len)
{
	int done = 0;
	uint8_t *buf_u8 = (uint8_t*)buf;
	while(done < len)
	{
		size_t write_size = len - done;
		int result = IOSUHAX_FSA_WriteFile(fsa_fd, buf_u8 + done, 0x01, write_size, fd, 0);
		if(result < 0)
			return result;
		else
			done += result;
	}
	return done;
}

struct DirName {
  char n[0x100];
};

extern "C" int Menu_Main(void)
{
	InitOSFunctionPointers();
	InitSysFunctionPointers();
	InitVPadFunctionPointers();
    VPADInit();

    // Init screen
    OSScreenInit();
    int screen_buf0_size = OSScreenGetBufferSizeEx(0);
    int screen_buf1_size = OSScreenGetBufferSizeEx(1);
	uint8_t *screenBuffer = (uint8_t*)memalign(0x100, screen_buf0_size+screen_buf1_size);
    OSScreenSetBufferEx(0, screenBuffer);
    OSScreenSetBufferEx(1, (screenBuffer + screen_buf0_size));
    OSScreenEnableEx(0, 1);
    OSScreenEnableEx(1, 1);
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);

    println(0,"tik2sd v1.1 by FIX94");
	println(2,"Press A to backup your console tickets.");
	println(3,"Press B to backup your current disc ticket.");

    int vpadError = -1;
    VPADData vpad;
	//wait for user to decide option
	int action = 0;
    while(1)
    {
        VPADRead(0, &vpad, 1, &vpadError);

        if(vpadError == 0)
		{
			if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
			{
				free(screenBuffer);
				return EXIT_SUCCESS;
			}
			else if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_A)
				break;
			else if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_B)
			{
				action = 1;
				break;
			}
		}
		usleep(50000);
    }

	int line = 5;
	//will inject our custom mcp code
	println(line++,"Doing IOSU Exploit...");
	IOSUExploit();

	int fsaFd = -1;
	int sdMounted = 0, oddMounted = 0;
	int sdFd = -1, tikFd = -1;
	int ret;
	size_t i;
	std::vector<DirName> dirNames;
	std::set<std::string> tKeys;
	directoryEntry_s data;

	//done with iosu exploit, take over mcp
	if(MCPHookOpen() < 0)
	{
		println(line++,"MCP hook could not be opened!");
		goto prgEnd;
	}
	println(line++,"Done!");

	//mount with full permissions
	fsaFd = IOSUHAX_FSA_Open();
	if(fsaFd < 0)
	{
		println(line++,"FSA could not be opened!");
		goto prgEnd;
	}
	ret = IOSUHAX_FSA_Mount(fsaFd, "/dev/sdcard01", sdCardVolPath, 2, (char*)0, 0);
	if(ret < 0)
	{
		println(line++,"Failed to mount SD!");
		goto prgEnd;
	}
	else
		sdMounted = 1;
	char sd2tikPath[256];
	sprintf(sd2tikPath,"%s/tik2sd",sdCardVolPath);
	IOSUHAX_FSA_MakeDir(fsaFd, sd2tikPath, 0x600);
	if(action == 0)
	{
		int handle;
		if(IOSUHAX_FSA_OpenDir(fsaFd, tikPath, &handle) < 0)
		{
			println(line++,"Failed to open tik folder!");
			goto prgEnd;
		}
		while(1)
		{
			directoryEntry_s data;
			ret = IOSUHAX_FSA_ReadDir(fsaFd, handle, &data);
			if(ret != 0)
				break;
			if(data.stat.flag & DIR_ENTRY_IS_DIRECTORY)
			{
				DirName cD;
				memcpy(cD.n, data.name, 0xFF);
				cD.n[0xFF] = '\0';
				dirNames.push_back(cD);
			}
		}
		IOSUHAX_FSA_CloseDir(fsaFd, handle);
		for(i = 0; i < dirNames.size(); i++)
		{
			char tikFolderPath[256];
			sprintf(tikFolderPath, "%s/%s", tikPath, dirNames[i].n);
			if(IOSUHAX_FSA_OpenDir(fsaFd, tikFolderPath, &handle) < 0)
				continue;
			char sdTikFolderPath[256];
			sprintf(sdTikFolderPath, "%s/%s", sd2tikPath, dirNames[i].n);
			IOSUHAX_FSA_MakeDir(fsaFd, sdTikFolderPath, 0x600);
			while(1)
			{
				ret = IOSUHAX_FSA_ReadDir(fsaFd, handle, &data);
				if(ret != 0)
					break;
				if(!(data.stat.flag & DIR_ENTRY_IS_DIRECTORY))
				{
					char tikRpath[256];
					sprintf(tikRpath, "%s/%s", tikFolderPath, data.name);
					if(IOSUHAX_FSA_OpenFile(fsaFd, tikRpath, "rb", &tikFd) >= 0)
					{
						fileStat_s stats;
						IOSUHAX_FSA_StatFile(fsaFd, tikFd, &stats);
						size_t tikLen = stats.size;
						uint8_t *tikBuf = (uint8_t*)malloc(tikLen);
						fsa_read(fsaFd, tikFd, tikBuf, tikLen);
						IOSUHAX_FSA_CloseFile(fsaFd, tikFd);
						tikFd = -1;
						bool checkTik = true;
						int tikP = 0;
						while(checkTik == true)
						{
							checkTik = false;
							uint8_t *curTik = tikBuf+tikP;
							if((*(uint32_t*)curTik) != 0x00010004)
								break;
							char tName[256];
							sprintf(tName, "%s/%s", dirNames[i].n, data.name);
							char tEntry[256];
							sprintf(tEntry, "%08x%08x %08x%08x%08x%08x (%s@0x%x)\n", (*(uint32_t*)(curTik+0x1DC)), (*(uint32_t*)(curTik+0x1E0)),
								(*(uint32_t*)(curTik+0x1BF)), (*(uint32_t*)(curTik+0x1C3)), (*(uint32_t*)(curTik+0x1C7)), (*(uint32_t*)(curTik+0x1CB)),
								tName, tikP);
							tKeys.insert(std::string(tEntry));
							if((tikLen-tikP) > 0x354)
							{
								if((*(uint16_t*)(curTik+0x2B0)) == 0 && (*(uint32_t*)(curTik+0x2B8)) == 0x00010004)
								{
									tikP += 0x2B8;
									checkTik = true;
								}
								else if((*(uint16_t*)(curTik+0x2B0)) == 1 && (*(uint32_t*)(curTik+0x350)) == 0x00010004)
								{
									tikP += 0x350;
									checkTik = true;
								}
							}
						}
						char tikWpath[256];
						sprintf(tikWpath, "%s/%s", sdTikFolderPath, data.name);
						if(IOSUHAX_FSA_OpenFile(fsaFd, tikWpath, "wb", &sdFd) >= 0)
						{
							fsa_write(fsaFd, sdFd, tikBuf, tikLen);
							IOSUHAX_FSA_CloseFile(fsaFd, sdFd);
							sdFd = -1;
						}
						free(tikBuf);
					}
				}
			}
			IOSUHAX_FSA_CloseDir(fsaFd, handle);
		}
		char sdKeyPath[256];
		sprintf(sdKeyPath, "%s/keys.txt", sd2tikPath);
		if(IOSUHAX_FSA_OpenFile(fsaFd, sdKeyPath, "wb", &sdFd) >= 0)
		{
			char startMsg[64];
			sprintf(startMsg, "Found %i unique tickets\n", tKeys.size());
			fsa_write(fsaFd, sdFd, startMsg, strlen(startMsg));
			for(std::set<std::string>::iterator it = tKeys.begin(); it != tKeys.end(); ++it)
			{
				const char *k = it->c_str();
				fsa_write(fsaFd, sdFd, k, strlen(k));
			}
			IOSUHAX_FSA_CloseFile(fsaFd, sdFd);
			sdFd = -1;
		}
	}
	else
	{
		ret = IOSUHAX_FSA_Mount(fsaFd, "/dev/odd01", oddTikVolPath, 2, (char*)0, 0);
		if(ret < 0)
		{
			println(line++,"Failed to mount ODD!");
			goto prgEnd;
		}
		else
			oddMounted = 1;
		int handle;
		if(IOSUHAX_FSA_OpenDir(fsaFd, oddTikVolPath, &handle) < 0)
		{
			println(line++,"Failed to open tik folder!");
			goto prgEnd;
		}
		char sdTikFolderPath[256];
		sprintf(sdTikFolderPath, "%s/odd", sd2tikPath);
		IOSUHAX_FSA_MakeDir(fsaFd, sdTikFolderPath, 0x600);
		while(1)
		{
			directoryEntry_s data;
			ret = IOSUHAX_FSA_ReadDir(fsaFd, handle, &data);
			if(ret != 0)
				break;
			if(data.stat.flag & DIR_ENTRY_IS_DIRECTORY)
			{
				char tikRpath[256];
				sprintf(tikRpath,"%s/%s/title.tik", oddTikVolPath, data.name);
				if(IOSUHAX_FSA_OpenFile(fsaFd, tikRpath, "rb", &tikFd) >= 0)
				{
					fileStat_s stats;
					IOSUHAX_FSA_StatFile(fsaFd, tikFd, &stats);
					size_t tikLen = stats.size;
					uint8_t *tikBuf = (uint8_t*)malloc(tikLen);
					fsa_read(fsaFd, tikFd, tikBuf, tikLen);
					IOSUHAX_FSA_CloseFile(fsaFd, tikFd);
					tikFd = -1;
					if((*(uint32_t*)(tikBuf+0x1DC)) == 0x00050000)
					{
						char tikWpath[256];
						sprintf(tikWpath, "%s/%08x%08x.tik", sdTikFolderPath, (*(uint32_t*)(tikBuf+0x1DC)), (*(uint32_t*)(tikBuf+0x1E0)));
						if(IOSUHAX_FSA_OpenFile(fsaFd, tikWpath, "wb", &sdFd) >= 0)
						{
							fsa_write(fsaFd, sdFd, tikBuf, tikLen);
							IOSUHAX_FSA_CloseFile(fsaFd, sdFd);
							sdFd = -1;
						}
					}
					free(tikBuf);
				}
			}
		}
		IOSUHAX_FSA_CloseDir(fsaFd, handle);
	}
	println(line++,"Tickets backed up!");

prgEnd:
	//close down everything fsa related
	if(fsaFd >= 0)
	{
		if(sdFd >= 0)
			IOSUHAX_FSA_CloseFile(fsaFd, sdFd);
		if(tikFd >= 0)
			IOSUHAX_FSA_CloseFile(fsaFd, tikFd);
		if(sdMounted)
			IOSUHAX_FSA_Unmount(fsaFd, sdCardVolPath, 2);
		if(oddMounted)
			IOSUHAX_FSA_Unmount(fsaFd, oddTikVolPath, 2);
		IOSUHAX_FSA_Close(fsaFd);
	}
	//close out old mcp instance
	MCPHookClose();
	sleep(5);
	//will do IOSU reboot
    OSForceFullRelaunch();
    SYSLaunchMenu();
    OSScreenEnableEx(0, 0);
    OSScreenEnableEx(1, 0);
	free(screenBuffer);
    return EXIT_RELAUNCH_ON_LOAD;
}
