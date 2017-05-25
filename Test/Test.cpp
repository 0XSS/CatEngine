// Test.cpp : Defines the entry point for the console application.
//

/* MinGW build EXE with static library
G++ Test.cpp --std=c++11 -lCatEngine -lws2_32 -o Test.exe && Test.exe
*/

/*
#ifdef _UNICODE
  #undef _UNICODE
#endif*/

#include <Windows.h>
#include <tchar.h>
#include <conio.h>
#include <ctime>
#include <limits>
#include <memory>
#include <cstdio>
#include <limits>
#include <algorithm>
#include <iostream>

// Remove min & max macros
#ifdef min
  #undef minx
#endif
#ifdef max
  #undef max
#endif

#include <CatEngine.h>

#if defined(_MSC_VER) || !defined(__BCPLUSPLUS__)
  #pragma comment(lib, "CatEngine.lib")
#endif // _MSC_VER || __BCPLUSPLUS__

#define SEPERATOR() std::tcout << T("----------------------------------------") << std::endl;

  typedef int (WINAPI *PfnMessageBoxA)(HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT   uType);
  typedef int (WINAPI *PfnMessageBoxW)(HWND   hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT   uType);

  PfnMessageBoxA pfnMessageBoxA = nullptr;
  PfnMessageBoxW pfnMessageBoxW = nullptr;

  int WINAPI HfnMessageBoxA(HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT   uType)
  {
    lpText = "MessageBoxA -> Hooked";
    return pfnMessageBoxA(hWnd, lpText, lpCaption, uType);
  }

  int WINAPI HfnMessageBoxW(HWND   hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT   uType)
  {
    lpText = L"MessageBoxW -> Hooked";
    return pfnMessageBoxW(hWnd, lpText, lpCaption, uType);
  }

  /* MessageBoxA
  00000000778F12B8 | 48 83 EC 38              | sub rsp,38                                                                 |
  00000000778F12BC | 45 33 DB                 | xor r11d,r11d                                                              |
  00000000778F12BF | 44 39 1D 76 0E 02 00     | cmp dword ptr ds:[77912135],r11d                                           |
  00000000778F12C6 | 74 2E                    | je user32.778F12F6                                                         |
  00000000778F12C8 | 65 48 8B 04 25 30 00 00  | mov rax,qword ptr gs:[30]                                                  |
  00000000778F12D1 | 4C 8B 50 48              | mov r10,qword ptr ds:[rax+48]                                              |
  ---
  000000013F0D2888 | 44 39 1C 25 35 21 91 77  | cmp dword ptr ds:[77912135],r11d                                           |
  */

int _tmain(int argc, _TCHAR* argv[])
{
  // Determine Processor Architecture
  ce::eProcessorArchitecture arch = ce::ceGetProcessorArchitecture();
  if (arch == ce::PA_X64) {
    // Determine Wow64
    std::string s;
    s.clear();
    ce::eWow64 result = ce::ceIsWow64();
    if (result == ce::eWow64::WOW64_YES) {
      s.assign("WOW64");
    } 
    else if (result == ce::WOW64_NO) {
      s.assign("Non-WOW64");
    }
    else {
      s.assign("Unknown");
    }
    std::cout << ce::ceFormatA("Windows 64-bit (%s)", s.c_str()) << std::endl;
  }
  else if (arch == ce::PA_X86) {
    std::tcout << T("Windows 32-bit") << std::endl;
  }
  else {
    std::tcout << _T("Unknown") << std::endl;
  }

  // Determine encoding
  #ifdef _UNICODE
  printf("Encoding: UNICODE\n");
  #else
  printf("Encoding: ANSI\n");
  #endif // _UNICODE

  // Seperate
  std::cout << std::endl;
  std::tcout << _T("--- *.* ---") << std::endl;
  std::cout << std::endl;

  // Misc
  /*ce::ceBox(ce::ceGetConsoleWindow(), _T("I'm %s. I'm %d years old!"), _T("Vic P"), 25);
  ce::ceMsg(_T("I'm %s. I'm %d years old!"), _T("Vic P"), 25);

  std::tcout << ce::ceFormat(_T("I'm %s. I'm %d years old! (A)"), _T("Vic P"), 25) << std::endl;

  std::tcout  << ce::ceLowerString(_T("I Love You")) << std::endl;
  std::tcout << ce::ceUpperString(_T("I Love You")) << std::endl;
  
  std::tcout << ce::ceLastError() << std::endl;

  std::list<std::tstring>  l;

  l.clear();
  l = ce::ceSplitString(_T("THIS IS A SPLIT STRING"), _T(" "));
  for (auto e: l) std::tcout << e << _T("|");
  std::tcout << std::endl;
  
  l.clear();
  l = ce::ceMultiStringToList(_T("THIS\0IS\0A\0MULTI\0STRING\0\0"));
  for (auto& e: l) std::tcout << e << _T("|");
  std::tcout << std::endl;

  std::tcout << ce::ceTimeDateToString(time(NULL)) << std::endl;

  std::cout  << ce::ceToStringA(L"THIS IS A WIDE STRING") << std::endl;
  std::wcout << ce::ceToStringW("THIS IS AN ANSI STRING") << std::endl;

  std::tstring envValue = ce::ceGetEnviroment(_T("PATH"));
  auto env = ce::ceSplitString(envValue, _T(";"));
  for (auto e: env) {
    std::tcout << e << std::endl;
  }

  std::list<ce::ulong> PIDs;
  PIDs.clear();

  PIDs = ce::ceNameToPid(_T("Explorer.exe"));
  for (auto& PID: PIDs) {
    std::tcout << PID << std::endl;
  }

  if (!PIDs.empty()) {
    std::tcout  << ce::cePidToName(*PIDs.begin()) << std::endl;
  }*/

  // File/Directory
  /*const std::tstring FILE_DIR  =  _T("F:\\Vic's Workspace\\Documents\\");
  const std::tstring FILE_PATH =  _T("F:\\Vic's Workspace\\Documents\\IMRT.ppt");

  std::tcout  << (ce::ceDirectoryExists(FILE_DIR) ? _T("Directory is exist") : _T("Directory isn't exist")) << std::endl;
  std::tcout  << (ce::ceFileExists(FILE_PATH) ? _T("File is exist") : _T("File isn't exist")) << std::endl;

  std::tcout  << ce::ceFileType(FILE_PATH) << std::endl;

  std::tcout  << ce::ceExtractFilePath(FILE_PATH) << std::endl;
  std::tcout  << ce::ceExtractFilePath(FILE_PATH, false) << std::endl;

  std::tcout  << ce::ceExtractFileName(FILE_PATH) << std::endl;
  std::tcout  << ce::ceExtractFileName(FILE_PATH, false) << std::endl;

  std::tcout  << ce::ceGetCurrentDirectory() << std::endl;
  std::tcout  << ce::ceGetCurrentDirectory(false) << std::endl;

  std::tcout  << ce::ceGetCurrentFilePath() << std::endl;*/

  // Not complete
  /*std::list<ce::ulong> explorersPID = ce::ceNameToPid(T("explorer.exe"));
  if (explorersPID.size() == 0) {
    return 1;
  }

  ce::ulong explorerPID = *explorersPID.begin();

  std::cout  << std::hex << ce::ceRemoteGetModuleHandleA(explorerPID, "kernel32.dll") << std::endl;
  std::tcout << ce::ceLastError().c_str() << std::endl;

  std::wcout << std::hex << ce::ceRemoteGetModuleHandleW(explorerPID, L"kernel32.dll") << std::endl;
  std::tcout << ce::ceLastError().c_str() << std::endl;*/

  // CESocket
  /*ce::CESocket socket;

  const std::string REQ_HOST = "d.7-zip.org";
  std::string REQ_CONTENT;
  REQ_CONTENT.clear();
  REQ_CONTENT.append("GET /a/7z1700-src.7z\r\n");
  REQ_CONTENT.append("User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0\r\n");
  REQ_CONTENT.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,* / *;q=0.8\r\n");
  REQ_CONTENT.append("Accept-Language: en-US,en;q=0.5\r\n");
  REQ_CONTENT.append("Accept-Encoding: gzip, deflate\r\n");
  REQ_CONTENT.append("DNT: 1\r\n");
  REQ_CONTENT.append("Connection: keep-alive\r\n");
  REQ_CONTENT.append("Upgrade-Insecure-Requests: 1\r\n");
  REQ_CONTENT.append("If-Modified-Since: *\r\n");
  REQ_CONTENT.append("\r\n");

  if (socket.ceSocket(ce::SAF_INET, ce::ST_STREAM) != ce::CE_OK) {
    std::tcout << _T("Socket -> Create -> Failed") << std::endl;
    return 1;
  }

  if (socket.ceConnect(REQ_HOST, 80) != ce::CE_OK) {
    std::tcout << _T("Socket -> Connect -> Failed") << std::endl;
    return 1;
  }

  if (socket.ceSend(REQ_CONTENT.data(), int(REQ_CONTENT.length())) == SOCKET_ERROR) {
    std::tcout << _T("Socket -> Connect -> Failed") << std::endl;
    return 1;
  }

  ce::CEFileA src7z;
  src7z.ceInit("E:\\7z1700-src.7z", ce::eFileModeFlags::FM_CREATEALWAY);
  if (src7z.ceIsReady()) {
    ce::CEBinary D(1024);
    ce::IResult N = -1, nRecvBytes = 0;
    do {
      N = socket.ceRecv(D);
      if (N > 0) {
        src7z.ceWrite(D.GetpData(), D.GetUsedSize());
        nRecvBytes += N;
      }
    } while (N > 0);
    src7z.ceClose();
  }

  if (!socket.ceClose()) {
    std::tcout << _T("Socket -> Close -> Failed") << std::endl;
    return 1;
  }*/

  // CEDynHook
  /*ce::CEDynHook API[2];

  if (!API_ATTACH(API[0], user32.dll, MessageBoxA)) {
      std::cout << "API::ATTACH -> MessageBoxA -> Failure" << std::endl;
      return 1;
  }

  std::cout << "API::ATTACH -> MessageBoxA -> Success" << std::endl;

  if (!API_ATTACH(API[1], user32.dll, MessageBoxW)) {
      std::cout << "API::ATTACH -> MessageBoxW -> Failure" << std::endl;
      return 1;
  }

  std::cout << "API::ATTACH -> MessageBoxW -> Success" << std::endl;

  MessageBoxA(ce::ceGetConsoleWindow(), "The first message.", "A", MB_OK);
  MessageBoxW(ce::ceGetConsoleWindow(), L"The first message.", L"W", MB_OK);

  if (!API_DETACH(API[0], user32.dll, MessageBoxA)) {
      std::cout << "API::DETACH -> MessageBoxA -> Failure" << std::endl;
  }

  std::cout << "API::DETACH -> MessageBoxA -> Success" << std::endl;

  if (!API_DETACH(API[0], user32.dll, MessageBoxW)) {
      std::cout << "API::DETACH -> MessageBoxW -> Failure" << std::endl;
  }

  std::cout << "API::DETACH -> MessageBoxW -> Success" << std::endl;

  MessageBoxA(ce::ceGetConsoleWindow(), "The second message.", "A", MB_OK);
  MessageBoxW(ce::ceGetConsoleWindow(), L"The second message.", L"W", MB_OK);*/

  // CEIniFile
  /*ce::CEIniFile ini(ce::ceGetCurrentFilePath() + _T(".ini"));

  ini.ceSetCurrentSection(_T("Section"));

  std::list<std::tstring> l;
  l.clear();

  l = ini.ceReadSectionNames();
  for (auto i = l.begin(); i != l.end(); i++) {
    _tprintf(_T("[%s]\n"), (*i).c_str());
  }

  std::cout << std::endl;

  l = ini.ceReadSection();
  for (auto i = l.begin(); i != l.end(); i++) {
    _tprintf(_T("[%s]\n"), (*i).c_str());
  }

  printf("\n");

  if (ini.ceWriteInteger(_T("KeyInt"), 702)) {
    _tprintf(_T("KeyInt = %d\n"), ini.ceReadInteger(_T("KeyInt"), 0));
  }

  if (ini.ceWriteBool(_T("KeyBool"), true)) {
    _tprintf(_T("KeyBool = %s\n"), ini.ceReadBool(_T("KeyBool"), 0) ? _T("True") : _T("False"));
  }

  if (ini.ceWriteFloat(_T("KeyFloat"), 7.02f)) {
    _tprintf(_T("KeyFloat = %.2f\n"), ini.ceReadFloat(_T("KeyFloat"), 0.F));
  }

  if (ini.ceWriteString(_T("KeyString"), _T("Vic P."))) {
    std::tstring s = ini.ceReadString(_T("KeyString"), _T(""));
    _tprintf(_T("KeyString = '%s'\n"), s.c_str());
  }

  struct TStruct {
    char a;
    int b;
    float c;
  } Input = {
    'X',
    702,
    7.02f
  };
  
  if (ini.ceWriteStruct(_T("KeyStruct"), &Input, sizeof(Input))) {
    std::shared_ptr<void> p = ini.ceReadStruct(_T("KeyStruct"), sizeof(TStruct));
    TStruct * Output = (TStruct*)p.get();
    _tprintf(_T("Value = [%c, %d, %.2f]\n"), Output->a, Output->b, Output->c);
  }*/

  // CERegistry (It has not complete yet)
  /*ce::CERegistry reg(ce::HKLM, T("SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"));
  if (!reg.ceKeyExists()) {
    std::tcout << T("Reg -> Exist -> Failed") << ce::ceLastError() << std::endl;
    return 1;
  }

  if (!reg.ceOpenKey()) {
    std::tcout << T("Reg -> Open-> Failed") << ce::ceLastError() << std::endl;
    return 1;
  }

  reg.ceSetReflectionKey(ce::eRegReflection::RR_ENABLE);

  std::tcout << T("Is Reflection Disabled ? ")
             << (reg.ceQueryReflectionKey() == ce::eRegReflection::RR_DISABLED ? T("True") : T("False"))
             << std::endl;

  std::list<std::tstring> l;

  std::tcout << T("\n[ErrorPort] -> ");
  std::tstring result = reg.ceReadString(T("ErrorPort"), T("<No>"));
  std::tcout << result << std::endl;

  std::tcout << T("\n[MS]") << std::endl;
  l.clear();
  l = reg.ceReadMultiString(T("MS"), l);
  for (auto e: l) {
    std::tcout << e << std::endl;
  }

  std::tcout << T("\n[Keys]") << std::endl;
  l.clear();
  l = reg.ceEnumKeys();
  for (auto e : l) {
    std::tcout << e << std::endl;
  }

  std::tcout << _T("\n[Values]") << std::endl;
  l.clear();
  l = reg.ceEnumValues();
  for (auto e : l) {
    std::tcout << e << std::endl;
  }

  std::tcout << std::endl;

//   reg.ceWriteBinary("RegBinary", "1234567890", 10);
//   std::tcout << _T("RegBinary\t" << (char*)reg.ceReadBinary("RegBinary", nullptr).get() << std::endl;
// 
//   reg.ceWriteBool("RegBool", true);
//   std::tcout << _T("RegBool\t" << reg.ceReadBool("RegBool", false) << std::endl;
// 
//   reg.ceWriteExpandString("RegExpandString", "CatEngine = %CatEngine%");
//   std::tcout << _T("RegExpandString\t" << reg.ceReadExpandString("RegExpandString", "") << std::endl;
// 
//   reg.ceWriteFloat("RegFloat", 16.09F);
//   std::tcout << _T("RegFloat\t" << reg.ceReadFloat("RegFloat", 7.02F) << std::endl;
// 
//   reg.ceWriteInteger("RegInt", 1609);
//   std::tcout << _T("RegInt\t" << reg.ceReadInteger("RegInt", 702) << std::endl;
// 
//   l.clear();
//   l.push_back("String 1");
//   l.push_back("String 2");
//   l.push_back("String 3");
//   reg.ceWriteMultiString("RegMultiString", l);
//   l.clear();
//   std::tcout << _T("RegMultiString") << std::endl;
//   l = reg.ceReadMultiString("RegMultiString", l);
//   for (auto e: l) {
//     std::tcout << _T("\t" << e << std::endl;
//   }
// 
//   reg.ceWriteString("RegString", "This is a string");
//   std::tcout << _T("RegString\t" << reg.ceReadString("RegString", "") << std::endl;

  if (!reg.ceCloseKey()) {
    std::tcout << T("Reg -> Close ->Failed") << ce::ceLastError() << std::endl;
  }*/

  // Data Type Information
  /*std::tcout << (ceIsSigned(ce::UIntPtr) ? T("Signed") : T("Unsigned")) << std::endl;
  std::tcout << (ceIsExact(ce::UIntPtr) ? T("Exact") : T("Non-Exact")) << std::endl;
  std::tcout << ceGetDigits(ce::UIntPtr) << std::endl;
  std::tcout << std::hex << ceGetLowest(ce::UIntPtr) << std::endl;
  std::tcout << std::hex << ceGetHighest(ce::UIntPtr) << std::endl;*/

  // CEService
  /*if (!ce::ceIsAdministrator()) {
    std::tcout << _T("You are not Administrator") << std::endl;
  }
  else {
    std::tcout << _T("You are Administrator") << std::endl;

    // CEService (re-check)
    ce::CEService srv;

    if (srv.ceInitService()) {
      std::tcout << _T("Service -> Initialize -> Success") << std::endl;
    }
    else {
      std::tcout << _T("Service -> Initialize -> Failure") << ce::ceLastError() << std::endl;
    }

    std::cout << std::endl;

    std::tcout << _T("Enter to create service...") << std::endl;
    getch();
    if (srv.ceCreateService(_T("C:\\Windows\\System32\\drivers\\VBoxUSBMon.sys"))) {
      std::tcout << _T("Service -> Create -> Success") << std::endl;
    }
    else {
      std::tcout << _T("Service -> Create -> Failure") << ce::ceLastError() << std::endl;
    }

    std::cout << std::endl;
  
    std::tcout << _T("Enter to start service...") << std::endl;
    getch();
    if (srv.ceStartService()) {
      std::tcout << _T("Service -> Start -> Success") << std::endl;
    }
    else {
      std::tcout << _T("Service -> Start -> Failure") << ce::ceLastError() << std::endl;
    }

    std::cout << std::endl;

    std::tcout << _T("Enter to stop service...") << std::endl;
    getch();
    if (srv.ceStopService()) {
      std::tcout << _T("Service -> Stop -> Success") << std::endl;
    }
    else {
      std::tcout << _T("Service -> Stop -> Failure") << ce::ceLastError() << std::endl;
    }

    std::cout << std::endl;

    std::tcout << _T("Enter to close service...") << std::endl;
    getch();
    if (srv.ceCloseService()) {
      std::tcout << _T("Service -> Close -> Success") << std::endl;
    }
    else {
      std::tcout << _T("Service -> Close -> Failure") << ce::ceLastError() << std::endl;
    }

    std::cout << std::endl;

    if (srv.ceReleaseService()) {
      std::tcout << _T("Service -> Release -> Success") << std::endl;
    }
    else {
      std::tcout << _T("Service -> Release -> Failure") << ce::ceLastError() << std::endl;
    }

    std::cout << std::endl;
  }*/

  // CEFile
  /*const std::tstring FILE_NAME = _T("Test.txt");
  ce::CEFile file;

  std::string s = "This is a test string!";
  file.ceInit(FILE_NAME, ce::FM_CREATEALWAY);
  file.ceWrite(s.c_str(), (ce::ulong)s.length());
  file.ceClose();

  char D[MAXBYTE] = {0};
  file.ceInit(FILE_NAME, ce::FM_OPENEXISTING);
  file.ceRead(&D, sizeof(D));
  file.ceClose();

  std::tcout << T("D = ") << D << std::endl;*/

  // CEFileMapping
  /*ce::CEFileMapping fm;

  / *if (fm.ceInit() != ce::CE_OK) {
    std::tcout << _T("Init -> Failed ") << ce::ceLastError() << std::endl;
  }
  if (fm.ceCreate(_T("Global\\Sample"), 512) != ce::CE_OK) {
    std::tcout << _T("Create -> Failed ") << ce::ceLastError() << std::endl;
  }
  auto p = fm.ceView();
  if (p == nullptr) {
    std::tcout << _T("View -> Failed ") << ce::ceLastError() << std::endl;
  }* /

  if (fm.ceInit(true, _T("C:\\Intel\\Logs\\IntelGFX.log")) != ce::CE_OK) {
    std::tcout << _T("Init -> Failed ") << ce::ceLastError() << std::endl;
  }

  if (fm.ceCreate(_T("FM-IntelGFX.log"), fm.ceGetFileSize()) != ce::CE_OK) {
    std::tcout << _T("Create -> Failed ") << ce::ceLastError() << std::endl;
  }

  auto p = fm.ceView();
  if (p == nullptr) {
    std::tcout << _T("View -> Failed ") << ce::ceLastError() << std::endl;
  }

  if (p != nullptr) {
    ce::ceHexDump(p, fm.ceGetFileSize());
  }*/

  // CEPEFile
  /*// ce::CEPEFileT<ce::pe32> pe(_T("C:\\Program Files\\Process Hacker 2\\x86\\ProcessHacker.exe"));
  ce::CEPEFileT<ce::pe64> pe(_T("C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe"));

  ce::CEResult result = pe.ceParse();
  if (result != ce::CE_OK) {
    std::tstring s;
    if (result == 8) {
      s = _T(" (Used wrong type data for the current PE file format)");
    }
    if (result == 9) {
      s = _T(" (The curent type data was not supported)");
    }
    std::tcout << _T("ceParse -> Failure") << ce::ceLastError() << s << std::endl;
    return 1;
  }

  void* pBase = pe.ceGetpBase();
  if (pBase == nullptr) {
    std::tcout << _T("ceGetpBase -> Failure") << ce::ceLastError() << std::endl;
    return 1;
  }

  SEPERATOR()

  auto sections = pe.ceGetSetionHeaderList();
  if (sections.size() == 0) {
    std::tcout << _T("ceGetSetionHeaderList -> Failure") << ce::ceLastError() << std::endl;
    return 1;
  }

  for (auto section: sections) {
    printf("%+10s %08X %08X %08X %08X\n",
      section->Name,
      section->PointerToRawData,
      section->SizeOfRawData,
      section->VirtualAddress,
      section->Misc.VirtualSize
    );
  }

  SEPERATOR()

  auto pPEHeader = pe.ceGetpPEHeader();
  if (pPEHeader == nullptr) {
    std::tcout << _T("pPEHeader -> NULL") << std::endl;
    return 1;
  }

  auto IIDs = pe.ceGetImportDescriptorList();
  if (IIDs.size() == 0) {
    std::tcout << _T("ceGetImportDescriptorList -> Failure") << ce::ceLastError() << std::endl;
    return 1;
  }

  for (auto IID: IIDs) {
    printf("%+20s %08X %08X %08X %08X\n",
      ((char*)pBase + pe.ceRVA2Offset(IID->Name)),
      IID->Name,
      IID->FirstThunk,
      IID->OriginalFirstThunk,
      IID->Characteristics
    );
  }

  SEPERATOR()

  auto DLLs = pe.ceGetDLLInfoList();
  if (DLLs.size() == 0) {
    std::tcout << _T("ceGetDLLList -> Failure") << ce::ceLastError() << std::endl;
    return 1;
  }

  for (auto DLL: DLLs) {
    printf("%08X, '%s'\n", DLL.IIDID, DLL.Name.c_str());
  }

  SEPERATOR()

  auto Functions = pe.ceGetFunctionInfoList();
  if (Functions.size() == 0) {
    std::tcout << _T("ceGetFunctionInfoList -> Failure") << ce::ceLastError() << std::endl;
    return 1;
  }

  for (auto Function: Functions) {
    / *ce::ceMsgA(
      "IIDID = %08X, Hint = %04X, RVA = %016X, [%016X - 's']",
      Function.IIDID,
      Function.Hint,
      Function.RVA,
      Function.Ordinal
      //Function.Name.c_str()
    );* /
    OutputDebugStringA(Function.Name.c_str());
  }

  SEPERATOR()

  auto DLL = pe.ceFindImportedDLL("KERNEL32.DLL");
  if (DLL.Name != "") {
    printf("%08X, '%s'\n", DLL.IIDID, DLL.Name.c_str());
  }

  SEPERATOR()

  auto Function = pe.ceFindImportedFunction("GetLastError");
  if (Function.RVA != 0) {
    printf("%08X, %04X, %016X '%s'\n",
      Function.IIDID,
      Function.Hint,
      Function.RVA,
      Function.Name.c_str()
    );
  }*/

  return 0;
}
