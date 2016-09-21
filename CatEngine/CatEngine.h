/*****************************************************/
/*  Name:     CatEngine                              */
/*  Version:  1.0                                    */
/*  Platform: Windows                                */
/*  Type:     C++ Library for MSVC/MinGW/C++Builder  */
/*  Author:   Vic P. aka vic4key                     */
/*  Mail:     vic4key[at]gmail.com                   */
/*  Blog:     http://viclab.biz                      */
/*  Website:  http://cin1team.biz                    */
/*****************************************************/

#ifndef CATENGINE_H
#define CATENGINE_H

/* Notice for use CatEngine!!
  1. Just available on Windows 32-bit and 64-bit.
  2. Support MSVC++, C++ Builder, MingGW.
  3. Only support C++ compiler.
  4. If you compile by MinGW, remember to include lws2_32.
  5. Force BYTE alignment of structures.
  6. Use /MT (Multi-Threaded) option to link for code generation (?)
  7. Remember to use ce namespace.
*/

/* CatEngine Version */

#define CE_VERSION  0x01000000  // Version 1.00.0001
#define CATENGINE_VERSION CE_VERSION



/* The condition of CatEngine to use */

#if !defined(_WIN32) && !defined(_WIN64)
#error CatEngine just available for Windows (32-bit and 64-bit) platform
#endif // !defined(_WIN32) && !defined(_WIN64)

#ifndef __cplusplus
  #error CatEngine only support C++ compiler
#endif // __cplusplus



/* Header Inclusion */

#if defined(_MSC_VER)
#pragma once
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <WinSock.h>
#include <string>
#include <cstdio>
#include <vector>
#include <list>
#include <ctime>
#include <memory>
#include <algorithm>



/* CatEngine's configuration */

// MSVC
#ifdef _MSC_VER
  #pragma pack(1)     // Force byte alignment of structures
#endif

// C++ Builder
#ifdef __BCPLUSPLUS__
  #pragma option -a1  // Force byte alignment of structures
#endif

// MingGW
#ifdef __MINGW32__
  #pragma pack(1)     // Force byte alignment of structures
#endif



#ifdef _MSC_VER
  #pragma warning(disable: 4996)
  #pragma comment(lib, "ws2_32")
#endif // _MSC_VER



/* HDE */
// Hacker Disassembler Engine 32/64 C
// Copyright (c) 2008-2009, Vyacheslav Patkov
// Vyacheslav Patkov, thanks you so much !

// --- Begin of HDE --- //

namespace HDE32 {
  const uint32_t F_MODRM         = 0x00000001;
  const uint32_t F_SIB           = 0x00000002;
  const uint32_t F_IMM8          = 0x00000004;
  const uint32_t F_IMM16         = 0x00000008;
  const uint32_t F_IMM32         = 0x00000010;
  const uint32_t F_DISP8         = 0x00000020;
  const uint32_t F_DISP16        = 0x00000040;
  const uint32_t F_DISP32        = 0x00000080;
  const uint32_t F_RELATIVE      = 0x00000100;
  const uint32_t F_2IMM16        = 0x00000800;
  const uint32_t F_ERROR         = 0x00001000;
  const uint32_t F_ERROR_OPCODE  = 0x00002000;
  const uint32_t F_ERROR_LENGTH  = 0x00004000;
  const uint32_t F_ERROR_LOCK    = 0x00008000;
  const uint32_t F_ERROR_OPERAND = 0x00010000;
  const uint32_t F_PREFIX_REPNZ  = 0x01000000;
  const uint32_t F_PREFIX_REPX   = 0x02000000;
  const uint32_t F_PREFIX_REP    = 0x03000000;
  const uint32_t F_PREFIX_66     = 0x04000000;
  const uint32_t F_PREFIX_67     = 0x08000000;
  const uint32_t F_PREFIX_LOCK   = 0x10000000;
  const uint32_t F_PREFIX_SEG    = 0x20000000;
  const uint32_t F_PREFIX_ANY    = 0x3f000000;

  // ---

  const uint8_t PREFIX_SEGMENT_CS   = 0x2e;
  const uint8_t PREFIX_SEGMENT_SS   = 0x36;
  const uint8_t PREFIX_SEGMENT_DS   = 0x3e;
  const uint8_t PREFIX_SEGMENT_ES   = 0x26;
  const uint8_t PREFIX_SEGMENT_FS   = 0x64;
  const uint8_t PREFIX_SEGMENT_GS   = 0x65;
  const uint8_t PREFIX_LOCK         = 0xf0;
  const uint8_t PREFIX_REPNZ        = 0xf2;
  const uint8_t PREFIX_REPX         = 0xf3;
  const uint8_t PREFIX_OPERAND_SIZE = 0x66;
  const uint8_t PREFIX_ADDRESS_SIZE = 0x67;

  //---

  const uint8_t C_NONE    = 0x00;
  const uint8_t C_MODRM   = 0x01;
  const uint8_t C_IMM8    = 0x02;
  const uint8_t C_IMM16   = 0x04;
  const uint8_t C_IMM_P66 = 0x10;
  const uint8_t C_REL8    = 0x20;
  const uint8_t C_REL32   = 0x40;
  const uint8_t C_GROUP   = 0x80;
  const uint8_t C_ERROR   = 0xff;

  // ---

  const uint8_t PRE_ANY  = 0x00;
  const uint8_t PRE_NONE = 0x01;
  const uint8_t PRE_F2   = 0x02;
  const uint8_t PRE_F3   = 0x04;
  const uint8_t PRE_66   = 0x08;
  const uint8_t PRE_67   = 0x10;
  const uint8_t PRE_LOCK = 0x20;
  const uint8_t PRE_SEG  = 0x40;
  const uint8_t PRE_ALL  = 0xff;

  // ---

  const uint32_t DELTA_OPCODES      = 0x4a;
  const uint32_t DELTA_FPU_REG      = 0xf1;
  const uint32_t DELTA_FPU_MODRM    = 0xf8;
  const uint32_t DELTA_PREFIXES     = 0x130;
  const uint32_t DELTA_OP_LOCK_OK   = 0x1a1;
  const uint32_t DELTA_OP2_LOCK_OK  = 0x1b9;
  const uint32_t DELTA_OP_ONLY_MEM  = 0x1cb;
  const uint32_t DELTA_OP2_ONLY_MEM = 0x1da;

  // ---

  typedef struct {
    uint8_t len;
    uint8_t p_rep;
    uint8_t p_lock;
    uint8_t p_seg;
    uint8_t p_66;
    uint8_t p_67;
    uint8_t opcode;
    uint8_t opcode2;
    uint8_t modrm;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;
    union {
      uint8_t imm8;
      uint16_t imm16;
      uint32_t imm32;
    } imm;
    union {
      uint8_t disp8;
      uint16_t disp16;
      uint32_t disp32;
    } disp;
    uint32_t flags;
  } hde32s;
}

namespace HDE64 {
  const uint32_t F_MODRM         = 0x00000001;
  const uint32_t F_SIB           = 0x00000002;
  const uint32_t F_IMM8          = 0x00000004;
  const uint32_t F_IMM16         = 0x00000008;
  const uint32_t F_IMM32         = 0x00000010;
  const uint32_t F_IMM64         = 0x00000020;
  const uint32_t F_DISP8         = 0x00000040;
  const uint32_t F_DISP16        = 0x00000080;
  const uint32_t F_DISP32        = 0x00000100;
  const uint32_t F_RELATIVE      = 0x00000200;
  const uint32_t F_ERROR         = 0x00001000;
  const uint32_t F_ERROR_OPCODE  = 0x00002000;
  const uint32_t F_ERROR_LENGTH  = 0x00004000;
  const uint32_t F_ERROR_LOCK    = 0x00008000;
  const uint32_t F_ERROR_OPERAND = 0x00010000;
  const uint32_t F_PREFIX_REPNZ  = 0x01000000;
  const uint32_t F_PREFIX_REPX   = 0x02000000;
  const uint32_t F_PREFIX_REP    = 0x03000000;
  const uint32_t F_PREFIX_66     = 0x04000000;
  const uint32_t F_PREFIX_67     = 0x08000000;
  const uint32_t F_PREFIX_LOCK   = 0x10000000;
  const uint32_t F_PREFIX_SEG    = 0x20000000;
  const uint32_t F_PREFIX_REX    = 0x40000000;
  const uint32_t F_PREFIX_ANY    = 0x7f000000;

  // ---

  const uint8_t PREFIX_SEGMENT_CS   = 0x2e;
  const uint8_t PREFIX_SEGMENT_SS   = 0x36;
  const uint8_t PREFIX_SEGMENT_DS   = 0x3e;
  const uint8_t PREFIX_SEGMENT_ES   = 0x26;
  const uint8_t PREFIX_SEGMENT_FS   = 0x64;
  const uint8_t PREFIX_SEGMENT_GS   = 0x65;
  const uint8_t PREFIX_LOCK         = 0xf0;
  const uint8_t PREFIX_REPNZ        = 0xf2;
  const uint8_t PREFIX_REPX         = 0xf3;
  const uint8_t PREFIX_OPERAND_SIZE = 0x66;
  const uint8_t PREFIX_ADDRESS_SIZE = 0x67;

  // ---

  const uint8_t C_NONE    = 0x00;
  const uint8_t C_MODRM   = 0x01;
  const uint8_t C_IMM8    = 0x02;
  const uint8_t C_IMM16   = 0x04;
  const uint8_t C_IMM_P66 = 0x10;
  const uint8_t C_REL8    = 0x20;
  const uint8_t C_REL32   = 0x40;
  const uint8_t C_GROUP   = 0x80;
  const uint8_t C_ERROR   = 0xff;

  // ---

  const uint8_t PRE_ANY  = 0x00;
  const uint8_t PRE_NONE = 0x01;
  const uint8_t PRE_F2   = 0x02;
  const uint8_t PRE_F3   = 0x04;
  const uint8_t PRE_66   = 0x08;
  const uint8_t PRE_67   = 0x10;
  const uint8_t PRE_LOCK = 0x20;
  const uint8_t PRE_SEG  = 0x40;
  const uint8_t PRE_ALL  = 0xff;

  // ---

  const uint32_t DELTA_OPCODES      = 0x4a;
  const uint32_t DELTA_FPU_REG      = 0xfd;
  const uint32_t DELTA_FPU_MODRM    = 0x104;
  const uint32_t DELTA_PREFIXES     = 0x13c;
  const uint32_t DELTA_OP_LOCK_OK   = 0x1ae;
  const uint32_t DELTA_OP2_LOCK_OK  = 0x1c6;
  const uint32_t DELTA_OP_ONLY_MEM  = 0x1d8;
  const uint32_t DELTA_OP2_ONLY_MEM = 0x1e7;

  // ---

  typedef struct {
    uint8_t len;
    uint8_t p_rep;
    uint8_t p_lock;
    uint8_t p_seg;
    uint8_t p_66;
    uint8_t p_67;
    uint8_t rex;
    uint8_t rex_w;
    uint8_t rex_r;
    uint8_t rex_x;
    uint8_t rex_b;
    uint8_t opcode;
    uint8_t opcode2;
    uint8_t modrm;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;
    union {
      uint8_t imm8;
      uint16_t imm16;
      uint32_t imm32;
      uint64_t imm64;
    } imm;
    union {
      uint8_t disp8;
      uint16_t disp16;
      uint32_t disp32;
    } disp;
    uint32_t flags;
  } hde64s;
}

#ifdef __cplusplus
extern "C" {
  unsigned int hde32_disasm(const void *code, HDE32::hde32s *hs);
  unsigned int hde64_disasm(const void *code, HDE64::hde64s *hs);
}
#endif

namespace HDE {
  #ifdef _WIN64
    typedef HDE64::hde64s tagHDE;
    #define HDEDisasm(code, hs) hde64_disasm(code, hs)
  #else  // _WIN32
    typedef HDE32::hde32s tagHDE;
    #define HDEDisasm(code, hs) hde32_disasm(code, hs)
  #endif // _WIN64
};

// --- End of HDE --- //



/* TCHAR equivalents of STL string and stream classes */

namespace std {
  #ifdef _UNICODE
  #define tcerr           wcerr
  #define tcin            wcin
  #define tclog           wclog
  #define tcout           wcout

  typedef wstring         tstring;

  typedef wstringbuf      tstringbuf;
  typedef wstringstream   tstringstream;
  typedef wostringstream  tostringstream;
  typedef wistringstream  tistringstream;

  typedef wstreambuf      tstreambuf;

  typedef wistream        tistream;
  typedef wostream        tostream;
  typedef wiostream       tiostream;

  typedef wfilebuf        tfilebuf;
  typedef wfstream        tfstream;
  typedef wifstream       tifstream;
  typedef wofstream       tofstream;

  typedef wios            tios;
  #else   // !_UNICODE
  #define tcerr           cerr
  #define tcin            cin
  #define tclog           clog
  #define tcout           cout

  typedef string          tstring;

  typedef stringbuf       tstringbuf;
  typedef stringstream    tstringstream;
  typedef ostringstream   tostringstream;
  typedef istringstream   tistringstream;

  typedef streambuf       tstreambuf;

  typedef istream         tistream;
  typedef ostream         tostream;
  typedef iostream        tiostream;

  typedef filebuf         tfilebuf;
  typedef fstream         tfstream;
  typedef ifstream        tifstream;
  typedef ofstream        tofstream;

  typedef ios             tios;
  #endif  // _UNICODE

  template<typename T>
  std::string to_string(T v)
  {
    std::string s = "";
    return s;
  }

  template<typename T>
  std::wstring to_wstring(T v)
  {
    std::wstring ws = L"";
    return ws;
  }
} // namespace std

namespace ce {

/* CatEngine's Definition */

#define ceapi __stdcall

#ifdef _UNICODE
#define T(x)  L ## x
#else   // !_UNICODE
#define T(x)  x
#endif  // _UNICODE

#ifndef MAXPATH
#define MAXPATH MAX_PATH
#endif

#define MAX_NPROCESSES  512

#define KiB     1024;
#define MiB     KiB*KiB;
#define GiB     MiB*KiB;

#define KB      1000;
#define MB      KB*KB;
#define GB      MB*KB;

/* Other Defination */

#define ERROR_INCORRECT_SIZE             1462L

  /* CatEngine's Types */

  typedef int                 CEResult;
  typedef int                 IResult;

  typedef TCHAR               tchar;
  typedef wchar_t             wchar;

  // 32-bit Default Data Types
  typedef unsigned char       uchar;
  typedef unsigned short      ushort;
  typedef unsigned short      ushort;
  typedef unsigned int        uint;
  typedef unsigned long       ulong;
  typedef unsigned long long  ulonglong;

  // 32-bit Data Types
  typedef short               short32;
  typedef unsigned short      ushort32;
  typedef int                 int32;
  typedef unsigned int        uint32;
  typedef int                 long32;
  typedef unsigned int        ulong32;

  // 64-bit Data Types
  typedef __int32             short64;
  typedef unsigned __int32    ushort64;
  typedef __int64             int64;
  typedef unsigned __int64    uint64;
  typedef __int64             long64;
  typedef unsigned __int64    ulong64;

  // 86-64 Data Types
  typedef HALF_PTR            halfptr;
  typedef UHALF_PTR           uhalfptr;
  typedef INT_PTR             intptr;
  typedef UINT_PTR            uintptr;
  typedef LONG_PTR            longptr;
  typedef ULONG_PTR           ulongptr;

  typedef unsigned char       UChar;
  typedef HALF_PTR            HalfPtr;
  typedef UHALF_PTR           UHalfPtr;
  typedef INT_PTR             IntPtr;
  typedef UINT_PTR            UIntPtr;
  typedef LONG_PTR            LongPtr;
  typedef ULONG_PTR           ULongPtr;

  typedef unsigned int        pe32;
  typedef unsigned __int64    pe64;

  typedef CRITICAL_SECTION        TCriticalSection, *PCriticalSection;

  // PE File - Data Type

  const ulong MAX_IDD = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  typedef IMAGE_DOS_HEADER  TDosHeader, *PDosHeader;

  typedef IMAGE_FILE_HEADER TFileHeader, *PFileHeader;

  typedef _IMAGE_SECTION_HEADER TSectionHeader, *PSectionHeader;

  typedef IMAGE_IMPORT_BY_NAME  TImportByName, *PImportByName;

  typedef IMAGE_IMPORT_DESCRIPTOR TImportDescriptor, *PImportDescriptor;

  typedef IMAGE_DATA_DIRECTORY TDataDirectory, *PDataDirectory;

  // _IMAGE_OPTIONAL_HEADER

  template <typename T>
  struct TOptHeaderT {
    ushort  Magic;
    uchar   MajorLinkerVersion;
    uchar   MinorLinkerVersion;
    ulong   SizeOfCode;
    ulong   SizeOfInitializedData;
    ulong   SizeOfUninitializedData;
    ulong   AddressOfEntryPoint;
    ulong   BaseOfCode;
    ulong   BaseOfData;
    T       ImageBase;
    ulong   SectionAlignment;
    ulong   FileAlignment;
    ushort  MajorOperatingSystemVersion;
    ushort  MinorOperatingSystemVersion;
    ushort  MajorImageVersion;
    ushort  MinorImageVersion;
    ushort  MajorSubsystemVersion;
    ushort  MinorSubsystemVersion;
    ulong   Win32VersionValue;
    ulong   SizeOfImage;
    ulong   SizeOfHeaders;
    ulong   CheckSum;
    ushort  Subsystem;
    ushort  DllCharacteristics;
    T       SizeOfStackReserve;
    T       SizeOfStackCommit;
    T       SizeOfHeapReserve;
    T       SizeOfHeapCommit;
    ulong   LoaderFlags;
    ulong   NumberOfRvaAndSizes;
    TDataDirectory DataDirectory[MAX_IDD];
  };

  template<> struct TOptHeaderT<pe64> {
    ushort  Magic;
    uchar   MajorLinkerVersion;
    uchar   MinorLinkerVersion;
    ulong   SizeOfCode;
    ulong   SizeOfInitializedData;
    ulong   SizeOfUninitializedData;
    ulong   AddressOfEntryPoint;
    ulong   BaseOfCode;
    ulong64 ImageBase;
    ulong   SectionAlignment;
    ulong   FileAlignment;
    ushort  MajorOperatingSystemVersion;
    ushort  MinorOperatingSystemVersion;
    ushort  MajorImageVersion;
    ushort  MinorImageVersion;
    ushort  MajorSubsystemVersion;
    ushort  MinorSubsystemVersion;
    ulong   Win32VersionValue;
    ulong   SizeOfImage;
    ulong   SizeOfHeaders;
    ulong   CheckSum;
    ushort  Subsystem;
    ushort  DllCharacteristics;
    ulong64 SizeOfStackReserve;
    ulong64 SizeOfStackCommit;
    ulong64 SizeOfHeapReserve;
    ulong64 SizeOfHeapCommit;
    ulong   LoaderFlags;
    ulong   NumberOfRvaAndSizes;
    TDataDirectory DataDirectory[MAX_IDD];
  };

  /*template <typename T>
  typedef TOptHeaderT<T> *POptHeaderT;*/

  typedef TOptHeaderT<ulong32> TOptHeader32, *POptHeader32;
  typedef TOptHeaderT<ulong64> TOptHeader64, *POptHeader64;

  // IMAGE_NT_HEADERS

  template <typename T>
  struct TNtHeaderT {
    ulong Signature;
    TFileHeader FileHeader;
    TOptHeaderT<T> OptionalHeader;
  };

  /*template <typename T>
  typedef TNtHeaderT<T> *PNtHeaderT;*/

  typedef TNtHeaderT<ulong32> TNtHeader32, *PNtHeader32;
  typedef TNtHeaderT<ulong64> TNtHeader64, *PNtHeader64;

  // IMAGE_THUNK_DATA

  template <typename T>
  struct TThunkDataT {
    union {
      T ForwarderString;
      T Function;
      T Ordinal;
      T AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
  };

  /*template <typename T>
  typedef TThunkDataT<T> *PThunkDataT;*/

  typedef TThunkDataT<ulong32>  TThunkData32, *PThunkData32;
  typedef TThunkDataT<ulong64>  TThunkData64, *PThunkData64;

  // _PE_HEADER

  template <typename T>
  struct TPEHeaderT {
    // IMAGE_NT_HEADERS
    ulong  Signature;
    // IMAGE_FILE_HEADER
    ushort Machine;
    ushort NumberOfSections;
    ulong  TimeDateStamp;
    ulong  PointerToSymbolTable;
    ulong  NumberOfSymbols;
    ushort SizeOfOptionalHeader;
    ushort Characteristics;
    // IMAGE_OPTIONAL_HEADER
    ushort Magic;
    uchar  MajorLinkerVersion;
    uchar  MinorLinkerVersion;
    ulong  SizeOfCode;
    ulong  SizeOfInitializedData;
    ulong  SizeOfUninitializedData;
    ulong  AddressOfEntryPoint;
    ulong  BaseOfCode;
    ulong  BaseOfData; // Non-exist for 64-bit
    T  ImageBase;
    ulong  SectionAlignment;
    ulong  FileAlignment;
    ushort MajorOperatingSystemVersion;
    ushort MinorOperatingSystemVersion;
    ushort MajorImageVersion;
    ushort MinorImageVersion;
    ushort MajorSubsystemVersion;
    ushort MinorSubsystemVersion;
    ulong  Win32VersionValue;
    ulong  SizeOfImage;
    ulong  SizeOfHeaders;
    ulong  CheckSum;
    ushort SubSystem;
    ushort DllCharacteristics;
    T      SizeOfStackReserve;
    T      SizeOfStackCommit;
    T      SizeOfHeapReserve;
    T      SizeOfHeapCommit;
    ulong  LoaderFlags;
    ulong  NumberOfRvaAndSizes;
    // IMAGE_DATA_DIRECTORY
    TDataDirectory Export;
    TDataDirectory Import;
    TDataDirectory Resource;
    TDataDirectory Exception;
    TDataDirectory Security;
    TDataDirectory Basereloc;
    TDataDirectory Debug;
    TDataDirectory Copyright;
    TDataDirectory Architecture;
    TDataDirectory Globalptr;
    TDataDirectory TLS;
    TDataDirectory LoadConfig;
    TDataDirectory BoundImport;
    TDataDirectory IAT;
    TDataDirectory DelayImport;
    TDataDirectory ComDescriptor;
  };

  template<> struct TPEHeaderT<pe64> {
    // IMAGE_NT_HEADERS
    ulong  Signature;
    // IMAGE_FILE_HEADER
    ushort Machine;
    ushort NumberOfSections;
    ulong  TimeDateStamp;
    ulong  PointerToSymbolTable;
    ulong  NumberOfSymbols;
    ushort SizeOfOptionalHeader;
    ushort Characteristics;
    // IMAGE_OPTIONAL_HEADER
    ushort Magic;
    uchar  MajorLinkerVersion;
    uchar  MinorLinkerVersion;
    ulong  SizeOfCode;
    ulong  SizeOfInitializedData;
    ulong  SizeOfUninitializedData;
    ulong  AddressOfEntryPoint;
    ulong  BaseOfCode;
    /* ulong  BaseOfData; // Non-exist for 64-bit */
    ulong64 ImageBase;
    ulong  SectionAlignment;
    ulong  FileAlignment;
    ushort MajorOperatingSystemVersion;
    ushort MinorOperatingSystemVersion;
    ushort MajorImageVersion;
    ushort MinorImageVersion;
    ushort MajorSubsystemVersion;
    ushort MinorSubsystemVersion;
    ulong  Win32VersionValue;
    ulong  SizeOfImage;
    ulong  SizeOfHeaders;
    ulong  CheckSum;
    ushort SubSystem;
    ushort DllCharacteristics;
    ulong64 SizeOfStackReserve;
    ulong64 SizeOfStackCommit;
    ulong64 SizeOfHeapReserve;
    ulong64 SizeOfHeapCommit;
    ulong  LoaderFlags;
    ulong  NumberOfRvaAndSizes;
    // IMAGE_DATA_DIRECTORY
    TDataDirectory Export;
    TDataDirectory Import;
    TDataDirectory Resource;
    TDataDirectory Exception;
    TDataDirectory Security;
    TDataDirectory Basereloc;
    TDataDirectory Debug;
    TDataDirectory Copyright;
    TDataDirectory Architecture;
    TDataDirectory Globalptr;
    TDataDirectory TLS;
    TDataDirectory LoadConfig;
    TDataDirectory BoundImport;
    TDataDirectory IAT;
    TDataDirectory DelayImport;
    TDataDirectory ComDescriptor;
  };

  /*template <typename T>
  typedef TPEHeaderT<T> *PTPEHeaderT;*/

  typedef TPEHeaderT<ulong32> TPEHeader32, *PPEHeader32;
  typedef TPEHeaderT<ulong64> TPEHeader64, *PPEHeader64;

  typedef struct _PROCESSENTRY32A {
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;          // this process
    ULONG   th32DefaultHeapID;
    DWORD   th32ModuleID;           // associated exe
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;    // this process's parent process
    LONG    pcPriClassBase;         // Base priority of process's threads
    DWORD   dwFlags;
    CHAR    szExeFile[MAX_PATH];    // Path
  } TProcessEntry32A, *PProcessEntry32A;

  typedef struct _PROCESSENTRY32W {
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;          // this process
    ULONG	th32DefaultHeapID;
    DWORD   th32ModuleID;           // associated exe
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;    // this process's parent process
    LONG    pcPriClassBase;         // Base priority of process's threads
    DWORD   dwFlags;
    WCHAR   szExeFile[MAX_PATH];    // Path
  } TProcessEntry32W, *PProcessEntry32W;

#define MAX_MODULE_NAME32 255

  typedef struct _MODULEENTRY32A {
    DWORD   dwSize;
    DWORD   th32ModuleID;       // This module
    DWORD   th32ProcessID;      // owning process
    DWORD   GlblcntUsage;       // Global usage count on the module
    DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
    BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
    DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
    HMODULE hModule;            // The hModule of this module in th32ProcessID's context
    char    szModule[MAX_MODULE_NAME32 + 1];
    char    szExePath[MAX_PATH];
  } TModuleEntry32A, *PModuleEntry32A;

  typedef struct _MODULEENTRY32W {
    DWORD   dwSize;
    DWORD   th32ModuleID;       // This module
    DWORD   th32ProcessID;      // owning process
    DWORD   GlblcntUsage;       // Global usage count on the module
    DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
    BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
    DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
    HMODULE hModule;            // The hModule of this module in th32ProcessID's context
    WCHAR   szModule[MAX_MODULE_NAME32 + 1];
    WCHAR   szExePath[MAX_PATH];
  } TModuleEntry32W, *PModuleEntry32W;

  /* The common types (32-bit & 64-bit)  */
#ifdef _WIN64
  typedef TNtHeader64   TNtHeader, *PNtHeader;
  typedef TOptHeader64  TOptHeader, *POptHeader;
  typedef TThunkData64  TThunkData, *PThunkData;
  typedef TPEHeader64   TPEHeader, *PPEHeader;
#else // _WIN32
  typedef TNtHeader32   TNtHeader, *PNtHeader;
  typedef TOptHeader32  TOptHeader, *POptHeader;
  typedef TThunkData32  TThunkData, *PThunkData;
  typedef TPEHeader32   TPEHeader, *PPEHeader;
#endif

  typedef struct _SERVICE_STATUS TServiceStatus;



  /* CatEngine's Constants */

  const CEResult CE_OK  = 0;

  /* CatEngine's Enumerates */

  #ifndef PROCESSOR_ARCHITECTURE_NEUTRAL
    #define PROCESSOR_ARCHITECTURE_NEUTRAL 11
  #endif

  typedef enum _PROCESSOR_ARCHITECTURE {
    PA_X86      = PROCESSOR_ARCHITECTURE_INTEL,
    PA_MIPS     = PROCESSOR_ARCHITECTURE_MIPS,
    PA_ALPHA    = PROCESSOR_ARCHITECTURE_ALPHA,
    PA_PPC      = PROCESSOR_ARCHITECTURE_PPC,
    PA_SHX      = PROCESSOR_ARCHITECTURE_SHX,
    PA_ARM      = PROCESSOR_ARCHITECTURE_ARM,
    PA_ITANIUM  = PROCESSOR_ARCHITECTURE_IA64,
    PA_ALPHA64  = PROCESSOR_ARCHITECTURE_ALPHA64,
    PA_MSIL     = PROCESSOR_ARCHITECTURE_MSIL,
    PA_X64      = PROCESSOR_ARCHITECTURE_AMD64,
    PA_WOW64    = PROCESSOR_ARCHITECTURE_IA32_ON_WIN64,
    PA_NEUTRAL  = PROCESSOR_ARCHITECTURE_NEUTRAL,
    PA_UNKNOWN  = PROCESSOR_ARCHITECTURE_UNKNOWN
  } eProcessorArchitecture;

  typedef enum _WOW64 {
    WOW64_ERROR = -1,
    WOW64_NO    = 0,
    WOW64_YES   = 1
  } eWow64;

  // CCatFile

  typedef enum _FILE_MODE_FLAGS {
    FM_CREATENEW = 1,    // CREATE_NEW         = 1,
    FM_CREATEALWAY,      // CREATE_ALWAYS      = 2,
    FM_OPENEXISTING,     // OPEN_EXISTING      = 3,
    FM_OPENALWAYS,       // OPEN_ALWAYS        = 4,
    FM_TRUNCATEEXISTING, // TRUNCATE_EXISTING  = 5,
  } eFileModeFlags;

  typedef enum _FILE_ATTRIBUTE_FLAGS {
    FA_UNKNOWN       = 0X00000000,
    FA_READONLY      = 0X00000001,   // FILE_ATTRIBUTE_READONLY             = $00000001;
    FA_HIDDEN        = 0X00000002,   // FILE_ATTRIBUTE_HIDDEN               = $00000002;
    FA_SYSTEM        = 0X00000004,   // FILE_ATTRIBUTE_SYSTEM               = $00000004;
    //FA_DIRECTORY     = 0X00000010, // FILE_ATTRIBUTE_DIRECTORY            = $00000010;
    FA_ARCHIVE       = 0X00000020,   // FILE_ATTRIBUTE_ARCHIVE              = $00000020;
    //FA_DEVICE      = 0X00000040,   // FILE_ATTRIBUTE_DEVICE               = $00000040;
    FA_NORM          = 0X00000080,   // FILE_ATTRIBUTE_NORMAL               = $00000080;
    FA_TEMPORARY     = 0X00000100,   // FILE_ATTRIBUTE_TEMPORARY            = $00000100;
    //FA_SPARSEFILE    = 0X00000200, // FILE_ATTRIBUTE_SPARSE_FILE          = $00000200;
    //FA_REPARSEPOINT  = 0X00000400, // FILE_ATTRIBUTE_REPARSE_POINT        = $00000400;
    FA_COMPRESSED    = 0X00000800,   // FILE_ATTRIBUTE_COMPRESSED           = $00000800;
    FA_OFFLINE       = 0X00001000,   // FILE_ATTRIBUTE_OFFLINE              = $00001000;
    //FANOTCONTENTINDEXED = 0X00002000, // FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  = $00002000;
    //FAENCRYPTED     = 0X00004000, // FILE_ATTRIBUTE_ENCRYPTED            = $00004000;
  } eFileAttributeFlags;

  typedef enum _FILE_SHARE_FLAGS {
    FS_NONE       = 0X00000000,
    FS_READ       = 0X00000001,
    FS_WRITE      = 0X00000002,
    FS_DELETE     = 0X00000004,
    FS_READWRITE  = FS_READ | FS_WRITE,
    FS_ALLACCESS  = FS_READ | FS_WRITE | FS_DELETE
  } eFileShareFlags;

  typedef enum _MOVE_METHOD_FLAGS {
    MM_BEGIN   = FILE_BEGIN,
    MM_CURRENT = FILE_CURRENT,
    MM_END     = FILE_END
  } eMoveMethodFlags;

  typedef enum _FILE_GENERIC_FLAGS {
    FG_ALL        = GENERIC_ALL,
    FG_EXECUTE    = GENERIC_EXECUTE,
    FG_WRITE      = GENERIC_WRITE,
    FG_READ       = GENERIC_READ,
    FG_READWRITE  = GENERIC_READ | GENERIC_WRITE
  } eFileGenericFlags;

  // CESocket

#define AF_IRDA   26
#define AF_INET6  23

  typedef enum _SOCKET_AF {
    SAF_UNSPEC    = AF_UNSPEC,
    SAF_INET      = AF_INET,
    SAF_IPX       = AF_IPX,
    SAF_APPLETALK = AF_APPLETALK,
    SAF_NETBIOS   = AF_NETBIOS,
    SAF_INET6     = AF_INET6,
    SAF_IRDA      = AF_IRDA,
    SAF_BTH       = AF_IRDA
  } eSocketAF;

  typedef enum _SOCKET_TYPE {
    ST_NONE      = 0,
    ST_STREAM    = SOCK_STREAM,
    ST_DGRAM     = SOCK_DGRAM,
    ST_RAW       = SOCK_RAW,
    ST_RDM       = SOCK_RDM,
    ST_SEQPACKET = SOCK_RDM
  } eSocketType;

#define BTHPROTO_RFCOMM 3
#define IPPROTO_ICMPV6  58
#define IPPROTO_RM      113

  typedef enum _SOCKET_PROTOCOL {
    SP_NONE    = 0,
    SP_CMP     = IPPROTO_ICMP,
    SP_IGMP    = IPPROTO_IGMP,
    SP_RFCOMM  = BTHPROTO_RFCOMM,
    SP_TCP     = IPPROTO_TCP,
    SP_UDP     = IPPROTO_UDP,
    SP_ICMPV6  = IPPROTO_ICMPV6,
    SP_RM      = IPPROTO_RM,
  } eSocketProtocol;

#define MSG_WAITALL     0x8
#define MSG_INTERRUPT   0x10
#define MSG_PARTIAL     0x8000

  typedef enum _SOCKET_MESSAGE {
    SM_NONE      = 0,
    SM_OOB       = MSG_OOB,
    SM_PEEK      = MSG_PEEK,
    SM_DONTROUTE = MSG_DONTROUTE,
    SM_WAITALL   = MSG_WAITALL,
    SM_PARTIAL   = MSG_PARTIAL,
    SM_INTERRUPT = MSG_INTERRUPT,
    SM_MAXIOVLEN = MSG_MAXIOVLEN
  } eSocketMessage;

  typedef enum _SHUTDOWN_FLAG {
    SF_UNKNOWN = -1,
    SF_RECEIVE = 0,
    SF_SEND,
    SF_BOTH
  } eShutdownFlag;

  // CEService

  typedef enum _SERVICE_ACCESS_TYPE {
    SAT_UNKNOWN              = -1,
    SAT_QUERY_CONFIG         = SERVICE_QUERY_CONFIG,
    SAT_CHANGE_CONFIG        = SERVICE_CHANGE_CONFIG,
    SAT_QUERY_STATUS         = SERVICE_QUERY_STATUS,
    SAT_ENUMERATE_DEPENDENTS = SERVICE_ENUMERATE_DEPENDENTS,
    SAT_START                = SERVICE_START,
    SAT_STOP                 = SERVICE_STOP,
    SAT_PAUSE_CONTINUE       = SERVICE_PAUSE_CONTINUE,
    SAT_INTERROGATE          = SERVICE_INTERROGATE,
    SAT_USER_DEFINED_CONTROL = SERVICE_USER_DEFINED_CONTROL,
    SAT_ALL_ACCESS           = SERVICE_ALL_ACCESS,
    SAT_DELETE               = DELETE
  } eServiceAccessType;

  typedef enum _SERVICE_TYPE {
    ST_UNKNOWN             = -1,
    ST_KERNEL_DRIVER       = SERVICE_KERNEL_DRIVER,
    ST_SYSTEM_DRIVER       = SERVICE_FILE_SYSTEM_DRIVER,
    ST_ADAPTER             = SERVICE_ADAPTER,
    ST_RECOGNIZER_DRIVER   = SERVICE_RECOGNIZER_DRIVER,
    ST_WIN32_OWN_PROCESS   = SERVICE_WIN32_OWN_PROCESS,
    ST_WIN32_SHARE_PROCESS = SERVICE_WIN32_SHARE_PROCESS
  } eServiceType;

  typedef enum _SERVICE_STATE {
    SS_UNKNOWN          = -1,
    SS_STOPPED          = SERVICE_STOPPED,
    SS_START_PENDING    = SERVICE_START_PENDING,
    SS_STOP_PENDING     = SERVICE_STOP_PENDING,
    SS_RUNNING          = SERVICE_RUNNING,
    SS_CONTINUE_PENDING = SERVICE_CONTINUE_PENDING,
    SS_PAUSE_PENDING    = SERVICE_PAUSE_PENDING,
    SS_PAUSED           = SERVICE_PAUSED
  } eServiceState;

  #ifndef SERVICE_CONTROL_PRESHUTDOWN
    #define SERVICE_CONTROL_PRESHUTDOWN 0x0000000F
  #endif

  #ifndef SERVICE_CONTROL_TIMECHANGE
    #define SERVICE_CONTROL_TIMECHANGE  0x00000010
  #endif

  #ifndef SERVICE_CONTROL_TRIGGEREVENT
    #define SERVICE_CONTROL_TRIGGEREVENT  0x00000020
  #endif

  typedef enum _SERVICE_CONTROL {
    SC_STOP                  = SERVICE_CONTROL_STOP,
    SC_PAUSE                 = SERVICE_CONTROL_PAUSE,
    SC_CONTINUE              = SERVICE_CONTROL_CONTINUE,
    SC_INTERROGATE           = SERVICE_CONTROL_INTERROGATE,
    SC_SHUTDOWN              = SERVICE_CONTROL_SHUTDOWN,
    SC_PARAMCHANGE           = SERVICE_CONTROL_PARAMCHANGE,
    SC_NETBINDADD            = SERVICE_CONTROL_NETBINDADD,
    SC_NETBINDREMOVE         = SERVICE_CONTROL_NETBINDREMOVE,
    SC_NETBINDENABLE         = SERVICE_CONTROL_NETBINDENABLE,
    SC_NETBINDDISABLE        = SERVICE_CONTROL_NETBINDDISABLE,
    SC_DEVICEEVENT           = SERVICE_CONTROL_DEVICEEVENT,
    SC_HARDWAREPROFILECHANGE = SERVICE_CONTROL_HARDWAREPROFILECHANGE,
    SC_POWEREVENT            = SERVICE_CONTROL_POWEREVENT,
    SC_SESSIONCHANGE         = SERVICE_CONTROL_SESSIONCHANGE,
    SC_PRESHUTDOWN           = SERVICE_CONTROL_PRESHUTDOWN,
    SC_TIMECHANGE            = SERVICE_CONTROL_TIMECHANGE,
    SC_TRIGGEREVENT          = SERVICE_CONTROL_TRIGGEREVENT
  } eServiceControl;

  typedef enum _SERVICE_START_TYPE {
    SST_UNKNOWN      = -1,
    SST_BOOT_START   = SERVICE_BOOT_START,
    SST_SYSTEM_START = SERVICE_SYSTEM_START,
    SST_AUTO_START   = SERVICE_AUTO_START,
    SST_DEMAND_START = SERVICE_DEMAND_START,
    SST_DISABLED     = SERVICE_DISABLED
  } eServiceStartType;

  typedef enum _SERVICE_ERROR_CONTROL_TYPE {
    SE_UNKNOWN  = -1,
    SE_IGNORE   = SERVICE_ERROR_IGNORE,
    SE_NORMAL   = SERVICE_ERROR_NORMAL,
    SE_SEVERE   = SERVICE_ERROR_SEVERE,
    SE_CRITICAL = SERVICE_ERROR_CRITICAL
  } eServiceErrorControlType;

  typedef enum _SC_ACCESS_TYPE {
    SC_CONNECT            = SC_MANAGER_CONNECT,
    SC_CREATE_SERVICE     = SC_MANAGER_CREATE_SERVICE,
    SC_ENUMERATE_SERVICE  = SC_MANAGER_ENUMERATE_SERVICE,
    SC_LOCK               = SC_MANAGER_LOCK,
    SC_QUERY_LOCK_STATUS  = SC_MANAGER_QUERY_LOCK_STATUS,
    SC_MODIFY_BOOT_CONFIG = SC_MANAGER_MODIFY_BOOT_CONFIG,
    SC_ALL_ACCESS         = SC_MANAGER_ALL_ACCESS
  } eSCAccessType;

  // CERegistry

  typedef enum _HKEY : ulongptr {
    HKCR = (ulongptr)HKEY_CLASSES_ROOT,
    HKCU = (ulongptr)HKEY_CURRENT_USER,
    HKLM = (ulongptr)HKEY_LOCAL_MACHINE,
    HKU  = (ulongptr)HKEY_USERS,
    HKPD = (ulongptr)HKEY_PERFORMANCE_DATA,
    HKCF = (ulongptr)HKEY_CURRENT_CONFIG,
  } eRegRoot;

  #ifndef KEY_WOW64_64KEY
    #define KEY_WOW64_64KEY 0x0100
  #endif

  #ifndef KEY_WOW64_32KEY
    #define KEY_WOW64_32KEY 0x0200
  #endif

  #ifndef KEY_WOW64_RES
    #define KEY_WOW64_RES 0x0300
  #endif

  typedef enum _REG_ACCESS {
    RA_UNKNOWN            = -1,
    RA_QUERY_VALUE        = KEY_QUERY_VALUE,
    RA_SET_VALUE          = KEY_SET_VALUE,
    RA_CREATE_SUB_KEY     = KEY_CREATE_SUB_KEY,
    RA_ENUMERATE_SUB_KEYS = KEY_ENUMERATE_SUB_KEYS,
    RA_NOTIFY             = KEY_NOTIFY,
    RA_CREATE_LINK        = KEY_CREATE_LINK,
    RA_WOW64_64KEY        = KEY_WOW64_64KEY,
    RA_WOW64_32KEY        = KEY_WOW64_32KEY,
    RA_WOW64_RES          = KEY_WOW64_RES,
    RA_READ               = KEY_READ,
    RA_WRITE              = KEY_WRITE,
    RA_EXECUTE            = KEY_EXECUTE,
    RA_ALL_ACCESS         = KEY_ALL_ACCESS
  } eRegAccess;

  typedef enum _REG_REFLECTION {
    RR_ERROR    = -1,
    RR_DISABLED = 0,
    RR_ENABLED  = 1,
    RR_DISABLE  = 2,
    RR_ENABLE   = 3
  } eRegReflection;



  /* ------------------------------------------------ Public Macro(s) ------------------------------------------------ */

  #define ceLenOf(X) (sizeof(X) / sizeof(X[0]))

  #define ceIsSigned(T) (std::is_signed<T>())
  #define ceIsExact(T) (std::numeric_limits<T>::is_exact)
  #define ceGetLowest(T) (std::numeric_limits<T>::lowest())
  #define ceGetHighest(T) (std::numeric_limits<T>::max())
  #define ceGetDigits(T) (std::numeric_limits<T>::digits)

  /* ---------------------------------------------- Public Function(s) ---------------------------------------------- */

  /* --- Cat: Misc Working --- */
  bool ceapi ceIsAdministrator();
  std::string ceGetEnviromentA(const std::string EnvName);
  std::wstring ceGetEnviromentW(const std::wstring EnvName);

  /* --- Cat: Math Working --- */
  template <typename T>
  T operator&(T a, T b) {
    return (T)((int)a & (int)b);
  }

  template <typename T>
  T operator|(T a, T b) {
    return (T)((int)a | (int)b);
  }

  template <typename T>
  T operator^(T a, T b) {
    return (T)((int)a ^ (int)b);
  }

  template <typename T>
  T operator!(T a) {
    return (T)(!(int)a);
  }

  template <typename T>
  T operator~(T a) {
    return (T)(~(int)a);
  }

  bool ceapi ceIsFlagOn(ulongptr ulFlags, ulongptr ulFlag);
  intptr ceapi ceGCD(ulongptr count, ...); // UCLN
  intptr ceapi ceLCM(ulongptr count, ...); // BCNN
  void ceapi ceHexDump(void * Data, int Size);

  /* --- Cat: String Formatting --- */
  std::string ceapi ceFormatA(const std::string Format, ...);
  std::wstring ceapi ceFormatW(const std::wstring Format, ...);
  void ceapi ceMsgA(const std::string Format, ...);
  void ceapi ceMsgW(const std::wstring Format, ...);
  int ceapi ceBoxA(const std::string Format, ...);
  int ceapi ceBoxW(const std::wstring Format, ...);
  int ceapi ceBoxA(HWND hWnd, const std::string Format, ...);
  int ceapi ceBoxW(HWND hWnd, const std::wstring Format, ...);
  int ceapi ceBoxA(HWND hWnd, uint uType, const std::string Caption, const std::string Format, ...);
  int ceapi ceBoxW(HWND hWnd, uint uType, const std::wstring Caption, const std::wstring Format, ...);
  std::string ceapi ceLastErrorA(ulong ulErrorCode = -1);
  std::wstring ceapi ceLastErrorW(ulong ulErrorCode = -1);
  std::string ceapi ceFormatTimeDateToStringA(const time_t t, const std::string Format);
  std::wstring ceapi ceFormatTimeDateToStringW(const time_t t, const std::wstring Format);
  std::string ceapi ceTimeDateToStringA(const time_t t);
  std::wstring ceapi ceTimeDateToStringW(const time_t t);

  /* --- Cat: String Working --- */
  std::string ceapi ceLowerStringA(const std::string String);
  std::wstring ceapi ceLowerStringW(const std::wstring String);
  std::string ceapi ceUpperStringA(const std::string String);
  std::wstring ceapi ceUpperStringW(const std::wstring String);
  std::string ceapi cePwcToPac(const std::wstring String);
  std::wstring ceapi cePacToPwc(const std::string String);
  std::list<std::string> ceapi ceSplitStringA(const std::string String, const std::string Seperate);
  std::list<std::wstring> ceapi ceSplitStringW(const std::wstring lpcwszString, const std::wstring Seperate);
  std::list<std::string> ceapi ceMultiStringToListA(const char * lpcszMultiString);
  std::list<std::wstring> ceapi ceMultiStringToListW(const wchar_t * lpcwszMultiString);
  std::shared_ptr<char> ceapi ceListToMultiStringA(std::list<std::string> StringList);
  std::shared_ptr<wchar> ceapi ceListToMultiStringW(std::list<std::wstring> StringList);

  /* --- Cat: Process Working --- */
  HWND ceapi ceGetConsoleWindow();
  eProcessorArchitecture ceGetProcessorArchitecture();
  eWow64 ceapi ceIsWow64(ulong ulPID = (ulong)-1); /* -1: Error, 0: False, 1: True */
  std::list<ulong> ceapi ceNameToPidA(std::string ProcessName, ulong ulMaxProcessNumber = MAX_NPROCESSES);
  std::list<ulong> ceapi ceNameToPidW(std::wstring ProcessName, ulong ulMaxProcessNumber = MAX_NPROCESSES);
  std::string ceapi cePidToNameA(ulong ulPID);
  std::wstring ceapi cePidToNameW(ulong ulPID);
  HMODULE ceapi ceRemoteGetModuleHandleA(ulong ulPID, const std::string ModuleName);
  HMODULE ceapi ceRemoteGetModuleHandleW(ulong ulPID, const std::wstring ModuleName);
  bool ceapi ceRPM(HANDLE hProcess, void* lpAddress, void* lpBuffer, SIZE_T ulSize);
  bool ceapi ceRPM(ulong ulPID, void* lpAddress, void* lpBuffer, SIZE_T ulSize);
  bool ceapi ceWPM(HANDLE hProcess, void* lpAddress, const void* lpcBuffer, SIZE_T ulSize);
  bool ceapi ceWPM(ulong ulPID, void* lpAddress, const void* lpcBuffer, SIZE_T ulSize);

  /* --- Cat: File/Directory Working --- */
  bool ceapi ceDirectoryExistsA(const std::string Directory);
  bool ceapi ceDirectoryExistsW(const std::wstring Directory);
  bool ceapi ceFileExistsA(const std::string FilePath);
  bool ceapi ceFileExistsW(const std::wstring FilePath);
  std::string ceapi ceFileTypeA(const std::string FilePath);
  std::wstring ceapi ceFileTypeW(const std::wstring FilePath);
  std::string ceapi ceExtractFilePathA(const std::string FilePath, bool bIncludeSlash = true);
  std::wstring ceapi ceExtractFilePathW(const std::wstring FilePath, bool bIncludeSlash = true);
  std::string ceapi ceExtractFileNameA(const std::string FilePath, bool bIncludeExtension = true);
  std::wstring ceapi ceExtractFileNameW(const std::wstring FilePath, bool bIncludeExtension = true);
  std::string ceapi ceGetCurrentFilePathA();
  std::wstring ceapi ceGetCurrentFilePathW();
  std::string ceapi ceGetCurrentDirectoryA(bool bIncludeSlash = true);
  std::wstring ceapi ceGetCurrentDirectoryW(bool bIncludeSlash = true);

  /*-------------------- The definition of common Function(s) which compatible both ANSI & UNICODE -------------------*/

#ifdef _UNICODE
/* --- Cat: Misc Working --- */
#define ceGetEnviroment ceGetEnviromentW
/* --- Cat: String Formatting --- */
#define ceFormat ceFormatW
#define ceMsg ceMsgW
#define ceBox ceBoxW
#define ceLastError ceLastErrorW
#define ceTimeDateToString ceTimeDateToStringW
#define ceFormatTimeDateToString ceFormatTimeDateToStringW
/* --- Cat: String Working --- */
#define ceLowerString ceLowerStringW
#define ceUpperString ceUpperStringW
#define ceSplitString ceSplitStringW
#define ceMultiStringToList ceMultiStringToListW
#define ceListToMultiString ceListToMultiStringW
/* --- Cat: Process Working --- */
#define ceNameToPid ceNameToPidW
#define cePidToName cePidToNameW
#define ceRemoteGetModuleHandle ceRemoteGetModuleHandleW
  /* --- Cat: File/Directory Working --- */
#define ceDirectoryExists ceDirectoryExistsW
#define ceFileType ceFileTypeW
#define ceFileExists ceFileExistsW
#define ceExtractFilePath ceExtractFilePathW
#define ceExtractFileName ceExtractFileNameW
#define ceGetCurrentFilePath ceGetCurrentFilePathW
#define ceGetCurrentDirectory ceGetCurrentDirectoryW
#else
/* --- Cat: Misc Working --- */
#define ceGetEnviroment ceGetEnviromentA
/* --- Cat: String Formatting --- */
#define ceFormat ceFormatA
#define ceMsg ceMsgA
#define ceBox ceBoxA
#define ceLastError ceLastErrorA
#define ceTimeDateToString ceTimeDateToStringA
#define ceFormatTimeDateToString ceFormatTimeDateToStringA
  /* --- Cat: String Working --- */
#define ceLowerString ceLowerStringA
#define ceUpperString ceUpperStringA
#define ceSplitString ceSplitStringA
#define ceMultiStringToList ceMultiStringToListA
  /* --- Cat: Process Working --- */
#define ceNameToPid ceNameToPidA
#define cePidToName cePidToNameA
#define ceRemoteGetModuleHandle ceRemoteGetModuleHandleA
  /* --- Cat: File/Directory Working --- */
#define ceDirectoryExists ceDirectoryExistsA
#define ceMoveDirectory ceMoveDirectoryA
#define ceFileType ceFileTypeA
#define ceFileExists ceFileExistsA
#define ceExtractFilePath ceExtractFilePathA
#define ceExtractFileName ceExtractFileNameA
#define ceGetCurrentFilePath ceGetCurrentFilePathA
#define ceGetCurrentDirectory ceGetCurrentDirectoryA
#define ceMultiStringToList ceMultiStringToListA
#endif



  /* ----------------------------------------------- Public Class(es) ----------------------------------------------- */

  class CELastError
  {
  public:
    CELastError() : m_LastErrorCode(ERROR_SUCCESS) {};
    virtual ~CELastError() {};

    ulong ceapi ceGetLastErrorCode() {
      return m_LastErrorCode;
    }

  protected:
    ulong m_LastErrorCode;
  };

  /* --- Cat : Library --- */

  class CELibraryA : public CELastError {
  public:
    CELibraryA();
    CELibraryA(const std::string ModuleName);
    CELibraryA(const std::string ModuleName, const std::string RoutineName);
    virtual ~CELibraryA();

    bool  ceapi ceIsLibraryAvailable();
    void* ceapi ceGetRoutineAddress();
    void* ceapi ceGetRoutineAddress(const std::string RoutineName);
    void* ceapi ceGetRoutineAddress(const std::string ModuleName, const std::string RoutineName);
    static void* ceapi ceGetRoutineAddressFast(const std::string ModuleName, const std::string RoutineName);
  private:
    std::string m_ModuleName, m_RoutineName;
  protected:
  };

  class CELibraryW : public CELastError {
  public:
    CELibraryW();
    CELibraryW(const std::wstring ModuleName);
    CELibraryW(const std::wstring ModuleName, const std::wstring RoutineName);
    virtual ~CELibraryW();

    bool  ceapi ceIsLibraryAvailable();
    void* ceapi ceGetRoutineAddress();
    void* ceapi ceGetRoutineAddress(const std::wstring RoutineName);
    void* ceapi ceGetRoutineAddress(const std::wstring ModuleName, const std::wstring RoutineName);
    static void* ceapi ceGetRoutineAddressFast(const std::wstring ModuleName, const std::wstring RoutineName);
  private:
    std::wstring m_ModuleName, m_RoutineName;
  protected:
  };

  /* --- Cat : Socket --- */

const std::string CE_LOCALHOST = "127.0.0.1";

  typedef struct {
    SOCKET s;
    sockaddr_in sai;
    char ip[15];
  } TSocketInfomation;

  struct TAccessPoint {
    std::string Host;
    ushort Port;
  };

  class CESocket : public CELastError {
  private:
    WSADATA m_WSAData;
    SOCKET m_Socket;
    sockaddr_in m_Server;
    hostent m_Client;

    bool ceapi ceIsSocketValid(SOCKET socket);
  public:
    CESocket();
    CESocket(eSocketAF sockAF, eSocketType socketType);
    virtual ~CESocket();
    CEResult ceapi ceSocket(eSocketAF socketAF, eSocketType socketType, eSocketProtocol socketProtocol = SP_NONE);
    CEResult ceapi ceBind(const TAccessPoint accessPoint);
    CEResult ceapi ceBind(const std::string Address, ushort usNPort);
    CEResult ceapi ceListen(int iMaxConnection = SOMAXCONN);
    CEResult ceapi ceAccept(TSocketInfomation& socketInformation);
    CEResult ceapi ceConnect(const TAccessPoint accessPoint);
    CEResult ceapi ceConnect(const std::string Address, ushort usPort);
    IResult ceapi ceSend(const char * lpData, int iLength, eSocketMessage socketMessage = SM_NONE);
    IResult ceapi ceSend(const SOCKET c, const char * lpData, int iLength, eSocketMessage socketMessage = SM_NONE);
    IResult ceapi ceRecv(char* lpData, int iLength, eSocketMessage socketMessage = SM_NONE);
    IResult ceapi ceRecv(SOCKET c, char* lpData, int iLength, eSocketMessage socketMessage = SM_NONE);
    IResult ceapi ceSendTo(const char * lpData, int iLength, TSocketInfomation& socketInformation);
    IResult ceapi ceRecvFrom(char* lpData, int iLength, TSocketInfomation& socketInformation);
    bool ceapi ceClose(SOCKET socket = 0);
    SOCKET ceapi ceGetSocket();
    CEResult ceapi ceGetOption(int iLevel, int iOptName, std::string OptVal, int * lpiLength);
    CEResult ceapi ceSetOption(int iLevel, int iOptName, const std::string OptVal, int iLength);
    CEResult ceapi ceShutdown(eShutdownFlag shutdownFlag);
    std::string ceapi ceGetLocalHostName();
    std::string ceapi ceGetHostByName(const std::string Name);
    bool ceapi ceIsHostName(const std::string s);
    bool ceapi ceBytesToIP(TSocketInfomation& socketInformation);
  protected:
  };

  /* --- Cat: API Hooking --- */

  /* Note for 2 below macros:
    1. The prefix of redirection function must be : Hfn
    2. The prefix of real function pointer must be : pfn
  */
  #define API_ATTACH(O, M, F) O.ceAPIAttach(T( # M ), T( # F ), (void*)&Hfn ## F, (void**)&pfn ## F)
  #define API_DETACH(O, M, F) O.ceAPIDetach(T( # M ), T( # F ), (void**)&pfn ## F)

  class CEDynHookSupport {
  protected:
    typedef enum _MEMORY_ADDRESS_TYPE {
      MAT_NONE = 0,
      MAT_8    = 1,
      MAT_16   = 2,
      MAT_32   = 3,
      MAT_64   = 4
    } eMemoryAddressType;

    typedef struct _MEMORY_INSTRUCTION {
      ulong Offset;   // Offset of the current instruction.
      ulong Position; // Position of the memory address in the current instruction.
      eMemoryAddressType MemoryAddressType;
      union {         // Memory Instruction value.
        uchar   A8;
        ushort  A16;
        ulong   A32;
        ulong64 A64;
      } MAO;
      union {         // Memory Instruction value.
        uchar   A8;
        ushort  A16;
        ulong   A32;
        ulong64 A64;
      } MAN;
    } TMemoryInstruction;

    typedef struct _REDIRECT {
      ushort   JMP;
      ulong    Unknown;
      ulongptr Address;
    } TRedirect;

    bool m_Hooked;
    std::vector<TMemoryInstruction> m_ListMemoryInstruction;

    static const ulong JMP_OPCODE_SIZE = 6;

    #ifdef _M_IX86
    static const ulong MIN_HOOK_SIZE   = 10;
    #else  // _M_AMD64
    static const ulong MIN_HOOK_SIZE   = 14;
    #endif // _M_IX86
  public:
    CEDynHookSupport() : m_Hooked(false) {};
    virtual ~CEDynHookSupport(){};

    ulongptr ceapi ceJumpLen(ulongptr ulSrcAddress, ulongptr ulDestAddress);
    bool ceapi ceStartDetour(void* pProc, void* pHookProc, void** pOldProc);
    bool ceapi ceStopDetour(void* pProc, void** pOldProc);
  private:

    /**
     * To handle the memory instruction.
     * @param[in] hde     The HDE struct of the current instruction.
     * @param[in] offset  The offset of current instruction. From the head of the current function.
     * @return  True if current instruction is a memory struction, False if it is not.
     */
    bool ceapi ceHandleMemoryInstruction(const HDE::tagHDE& hde, const ulong offset);
  };

  class CEDynHookA: public CEDynHookSupport {
  public:
    CEDynHookA(){};
    virtual ~CEDynHookA(){};
    bool ceapi ceAPIAttach(
      const std::string ModuleName,
      const std::string ProcName,
      void* lpHookProc,
      void** lpOldProc
    );
    bool ceapi ceAPIDetach(
      const std::string ModuleName,
      const std::string ProcName,
      void** lpOldProc
    );
  };

  class CEDynHookW: public CEDynHookSupport {
  public:
    CEDynHookW(){};
    virtual ~CEDynHookW(){};
    bool ceapi ceAPIAttach(
      const std::wstring ModuleName,
      const std::wstring ProcName,
      void* lpHookProc,
      void** lpOldProc
      );
    bool ceapi ceAPIDetach(
      const std::wstring ModuleName,
      const std::wstring ProcName,
      void** lpOldProc
      );
  };

  /* --- Cat : File Working --- */

  class CEFileSupport : public CELastError {
  public:
    CEFileSupport(){};
    virtual ~CEFileSupport(){};
    virtual bool ceapi ceIsFileHandleValid(HANDLE fileHandle);
    virtual ulong ceapi ceGetFileSize();
    virtual bool ceapi ceRead(void* Buffer, ulong ulSize);
    virtual bool ceapi ceRead(
      ulong ulOffset,
      void* Buffer,
      ulong ulSize,
      eMoveMethodFlags mmFlag = MM_BEGIN
    );
    virtual bool ceapi ceWrite(const void* cBuffer, ulong ulSize);
    virtual bool ceapi ceWrite(
      ulong ulOffset,
      const void* cBuffer,
      ulong ulSize,
      eMoveMethodFlags mmFlag = MM_BEGIN
    );
    virtual bool ceapi ceSeek(ulong ulOffset, eMoveMethodFlags mmFlag);
    virtual bool ceapi ceIOControl(
      ulong ulControlCode,
      void* lpSendBuffer,
      ulong ulSendSize,
      void* lpReveiceBuffer,
      ulong ulReveiceSize
    );
    virtual bool ceapi ceClose();
  protected:
    HANDLE m_FileHandle;
  private:
    ulong m_ReadSize, m_WroteSize;
  };

  class CEFileA: public CEFileSupport {
  public:
    CEFileA(){};
    virtual ~CEFileA(){};
    bool ceapi ceInit(
      const std::string FilePath,
      eFileModeFlags fmFlag,
      eFileGenericFlags fgFlag   = FG_READWRITE,
      eFileShareFlags fsFlag     = FS_ALLACCESS,
      eFileAttributeFlags faFlag = FA_NORM
    );
  protected:
  };

  class CEFileW: public CEFileSupport {
  public:
    CEFileW(){};
    virtual ~CEFileW(){};
    bool ceapi ceInit(
      const std::wstring FilePath,
      eFileModeFlags fmFlag,
      eFileGenericFlags fgFlag = FG_READWRITE,
      eFileShareFlags fsFlag   = FS_ALLACCESS,
      eFileAttributeFlags faFlag = FA_NORM
    );
  protected:
  };

  /* --- Cat : Service Working --- */
  class CEServiceSupport : public CELastError {
  public:
    CEServiceSupport() : m_Initialized(false) {
      m_LastErrorCode = ERROR_SUCCESS;
    };
    virtual ~CEServiceSupport(){};

    bool ceapi ceInitService(eSCAccessType SCAccessType = eSCAccessType::SC_ALL_ACCESS);
    bool ceapi ceReleaseService();
    bool ceapi ceControlService(eServiceControl ServiceControl);
    bool ceapi ceStartService();
    bool ceapi ceStopService();
    bool ceapi ceCloseService();
    bool ceapi ceQueryServiceStatus(TServiceStatus& ServiceStatus);
    eServiceType ceapi ceGetServiceType();
    eServiceState ceapi ceGetServiceState();
  protected:
    SC_HANDLE m_SCMHandle, m_ServiceHandle;
    SERVICE_STATUS m_Status;
    bool m_Initialized;
  private:
  };

  class CEServiceA: public CEServiceSupport {
  public:
    CEServiceA();
    virtual ~CEServiceA();

    bool ceapi ceCreateService(
      const std::string ServiceFilePath,
      eServiceAccessType ServiceAccessType = SAT_ALL_ACCESS,
      eServiceType ServiceType = eServiceType::ST_KERNEL_DRIVER,
      eServiceStartType ServiceStartType = eServiceStartType::SST_DEMAND_START,
      eServiceErrorControlType ServiceErrorControlType = eServiceErrorControlType::SE_IGNORE
    );
    bool ceapi ceOpenService(
      const std::string ServiceName,
      eServiceAccessType ServiceAccessType = eServiceAccessType::SAT_ALL_ACCESS
    );
    std::string ceapi ceGetName(const std::string AnotherServiceDisplayName = "");
    std::string ceapi ceGetDisplayName(const std::string AnotherServiceName = "");
  private:
    std::string m_Name;
    std::string m_DisplayName;
    std::string m_ServiceName;
    std::string m_ServiceFileName;
    std::string m_ServiceFilePath;
  protected:
  };

  class CEServiceW: public CEServiceSupport {
  public:
    CEServiceW();
    virtual ~CEServiceW();

    bool ceapi ceCreateService(
      const std::wstring ServiceFilePath,
      eServiceAccessType ServiceAccessType = eServiceAccessType::SAT_ALL_ACCESS,
      eServiceType ServiceType = eServiceType::ST_KERNEL_DRIVER,
      eServiceStartType ServiceStartType = eServiceStartType::SST_DEMAND_START,
      eServiceErrorControlType ServiceErrorControlType = eServiceErrorControlType::SE_IGNORE
    );
    bool ceapi ceOpenService(
      const std::wstring ServiceName,
      eServiceAccessType ServiceAccessType = eServiceAccessType::SAT_ALL_ACCESS
    );
    std::wstring ceapi ceGetName(const std::wstring AnotherServiceDisplayName = L"");
    std::wstring ceapi ceGetDisplayName(const std::wstring AnotherServiceName = L"");
  private:
    std::wstring m_Name;
    std::wstring m_DisplayName;
    std::wstring m_ServiceName;
    std::wstring m_ServiceFileName;
    std::wstring m_ServiceFilePath;
  protected:
  };

  /* --- Cat : File Mapping --- */

  class CEFileMappingA : public CELastError {
  private:
    bool m_HasInit;
    HANDLE m_FileHandle;
    HANDLE m_MapHandle;
    void * m_pData;

    bool ceIsValidHandle(HANDLE Handle) {
      return (m_FileHandle != nullptr && m_FileHandle != INVALID_HANDLE_VALUE);
    }
  public:
    CEFileMappingA();
    virtual ~CEFileMappingA();
    CEResult ceapi ceInit(
      const std::string FileName,
      eFileGenericFlags fgFlag = FG_READWRITE,
      eFileShareFlags fsFlag   = FS_READWRITE
      );
    CEResult ceapi ceCreate(
      const std::string MapName,
      ulong ulMaxSizeHigh = 0,
      ulong ulMaxSizeLow  = 0
      );
    CEResult ceapi ceOpen(const std::string MapName, bool bInheritHandle);
    void* ceapi ceView(
      ulong ulMaxFileOffsetHigh  = 0,
      ulong ulMaxFileOffsetLow   = 0,
      ulong ulNumberOfBytesToMap = 0
      );
    ulong ceapi ceGetFileSize();
    void ceapi ceClose();
  };

  class CEFileMappingW : public CELastError {
  private:
    bool m_HasInit;
    HANDLE m_FileHandle;
    HANDLE m_MapHandle;
    void* m_pData;

    bool ceIsValidHandle(HANDLE Handle) {
      return (m_FileHandle != nullptr && m_FileHandle != INVALID_HANDLE_VALUE);
    }
  public:
    CEFileMappingW();
    virtual ~CEFileMappingW();
    CEResult ceapi ceInit(
      const std::wstring FileName,
      eFileGenericFlags fgFlag = FG_READWRITE,
      eFileShareFlags fsFlag   = FS_READWRITE
      );
    CEResult ceapi ceCreate(
      const std::wstring MapName,
      ulong ulMaxSizeHigh = 0,
      ulong ulMaxSizeLow  = 0
      );
    CEResult ceapi ceOpen(const std::wstring MapName, bool bInheritHandle);
    void* ceapi ceView(
      ulong ulMaxFileOffsetHigh  = 0,
      ulong ulMaxFileOffsetLow   = 0,
      ulong ulNumberOfBytesToMap = 0
      );
    ulong ceapi ceGetFileSize();
    void ceapi ceClose();
  };

  /* --- Cat : INI File --- */

  class CEIniFileA : public CELastError {
  private:
    std::string m_FilePath;
    std::string m_Section;

    void ceValidFilePath();
  public:
    CEIniFileA() {};
    CEIniFileA(const std::string FilePath);
    CEIniFileA(const std::string FilePath, const std::string Section);
    virtual ~CEIniFileA() {};

    void ceSetCurrentFilePath(const std::string FilePath);
    void ceSetCurrentSection(const std::string Section);

    std::list<std::string> ceapi ceReadSection(const std::string Section, ulong ulMaxSize = MAXBYTE);
    std::list<std::string> ceapi ceReadSection(ulong ulMaxSize = MAXBYTE);

    std::list<std::string> ceapi ceReadSectionNames(ulong ulMaxSize = MAXBYTE);

    int ceapi ceReadInteger(const std::string Section, const std::string Key, int Default);
    bool ceapi ceReadBool(const std::string Section, const std::string Key, bool Default);
    float ceapi ceReadFloat(const std::string Section, const std::string Key, float Default);
    std::string ceapi ceReadString(const std::string Section, const std::string Key, const std::string Default);
    std::shared_ptr<void> ceapi ceReadStruct(const std::string Section, const std::string Key, ulong ulSize);

    int ceapi ceReadInteger(const std::string Key, int Default);
    bool ceapi ceReadBool(const std::string Key, bool Default);
    float ceapi ceReadFloat(const std::string Key, float Default);
    std::string ceapi ceReadString(const std::string Key, const std::string Default);
    std::shared_ptr<void> ceapi ceReadStruct(const std::string Key, ulong ulSize);

    bool ceapi ceWriteInteger(const std::string Section, const std::string Key, int Value);
    bool ceapi ceWriteBool(const std::string Section, const std::string Key, bool Value);
    bool ceapi ceWriteFloat(const std::string Section, const std::string Key, float Value);
    bool ceapi ceWriteString(const std::string Section, const std::string Key, const std::string Value);
    bool ceapi ceWriteStruct(const std::string Section, const std::string Key, void* pStruct, ulong ulSize);

    bool ceapi ceWriteInteger(const std::string Key, int Value);
    bool ceapi ceWriteBool(const std::string Key, bool Value);
    bool ceapi ceWriteFloat(const std::string Key, float Value);
    bool ceapi ceWriteString(const std::string Key, const std::string Value);
    bool ceapi ceWriteStruct(const std::string Key, void* pStruct, ulong ulSize);
  protected:
  };

  class CEIniFileW : public CELastError {
  private:
    std::wstring m_FilePath;
    std::wstring m_Section;

    void ceValidFilePath();
  public:
    CEIniFileW() {};
    CEIniFileW(const std::wstring FilePath);
    CEIniFileW(const std::wstring FilePath, const std::wstring Section);
    virtual ~CEIniFileW() {};

    void ceSetCurrentFilePath(const std::wstring FilePath);
    void ceSetCurrentSection(const std::wstring Section);

    std::list<std::wstring> ceapi ceReadSection(const std::wstring Section, ulong ulMaxSize = MAXBYTE);
    std::list<std::wstring> ceapi ceReadSection(ulong ulMaxSize = MAXBYTE);

    std::list<std::wstring> ceapi ceReadSectionNames(ulong ulMaxSize = MAXBYTE);

    int ceapi ceReadInteger(const std::wstring Section, const std::wstring Key, int Default);
    bool ceapi ceReadBool(const std::wstring Section, const std::wstring Key, bool Default);
    float ceapi ceReadFloat(const std::wstring Section, const std::wstring Key, float Default);
    std::wstring ceapi ceReadString(const std::wstring Section, const std::wstring Key, const std::wstring Default);
    std::shared_ptr<void> ceapi ceReadStruct(const std::wstring Section, const std::wstring Key, ulong ulSize);

    int ceapi ceReadInteger(const std::wstring Key, int Default);
    bool ceapi ceReadBool(const std::wstring Key, bool Default);
    float ceapi ceReadFloat(const std::wstring Key, float Default);
    std::wstring ceapi ceReadString(const std::wstring Key, const std::wstring Default);
    std::shared_ptr<void> ceapi ceReadStruct(const std::wstring Key, ulong ulSize);

    bool ceapi ceWriteInteger(const std::wstring Section, const std::wstring Key, int Value);
    bool ceapi ceWriteBool(const std::wstring Section, const std::wstring Key, bool Value);
    bool ceapi ceWriteFloat(const std::wstring Section, const std::wstring Key, float Value);
    bool ceapi ceWriteString(const std::wstring Section, const std::wstring Key, const std::wstring Value);
    bool ceapi ceWriteStruct(const std::wstring Section, const std::wstring Key, void * pStruct, ulong ulSize);

    bool ceapi ceWriteInteger(const std::wstring Key, int Value);
    bool ceapi ceWriteBool(const std::wstring Key, bool Value);
    bool ceapi ceWriteFloat(const std::wstring Key, float Value);
    bool ceapi ceWriteString(const std::wstring Key, const std::wstring Value);
    bool ceapi ceWriteStruct(const std::wstring Key, void * pStruct, ulong ulSize);
  };

  /* --- Cat : Registry --- */

  class CERegistrySupport : public CELastError {
  public:
    CERegistrySupport() {
      m_LastErrorCode = ERROR_SUCCESS;
    };
    virtual ~CERegistrySupport() {};

    HKEY ceapi ceGetCurrentKeyHandle();
    eRegReflection ceapi ceQueryReflectionKey();
    bool ceapi ceSetReflectionKey(eRegReflection RegReflection);
    bool ceapi ceCloseKey();
  protected:
    HKEY m_HKRootKey;
    HKEY m_HKSubKey;
  };

  class CERegistryA : public CERegistrySupport {
    std::string m_SubKey;
  public:
    CERegistryA();
    CERegistryA(eRegRoot RegRoot);
    CERegistryA(eRegRoot RegRoot, const std::string SubKey);
    virtual ~CERegistryA() {};

    ulong ceapi ceGetSizeOfMultiString(const char * lpcszMultiString);
    ulong ceapi ceGetDataSize(const std::string ValueName, ulong ulType);

    bool ceapi ceCreateKey();
    bool ceapi ceCreateKey(const std::string SubKey);
    bool ceapi ceKeyExists();
    bool ceapi ceKeyExists(const std::string SubKey);
    bool ceapi ceOpenKey(eRegAccess RegAccess = eRegAccess::RA_ALL_ACCESS);
    bool ceapi ceOpenKey(const std::string SubKey, eRegAccess RegAccess = eRegAccess::RA_ALL_ACCESS);
    bool ceapi ceDeleteKey();
    bool ceapi ceDeleteKey(const std::string SubKey);
    bool ceapi ceDeleteValue(const std::string Value);

    std::list<std::string> ceapi ceEnumKeys();
    std::list<std::string> ceapi ceEnumValues();

    bool ceapi ceWriteInteger(const std::string ValueName, int Value);
    bool ceapi ceWriteBool(const std::string ValueName, bool Value);
    bool ceapi ceWriteFloat(const std::string ValueName, float Value);
    bool ceapi ceWriteString(const std::string ValueName, const std::string Value);
    bool ceapi ceWriteMultiString(const std::string ValueName, const char * lpValue);
    bool ceapi ceWriteMultiString(const std::string ValueName, const std::list<std::string> Value);
    bool ceapi ceWriteExpandString(const std::string ValueName, const std::string Value);
    bool ceapi ceWriteBinary(const std::string ValueName, void * pData, ulong ulSize);

    int ceapi ceReadInteger(const std::string ValueName, int Default);
    bool ceapi ceReadBool(const std::string ValueName, bool Default);
    float ceapi ceReadFloat(const std::string ValueName, float Default);
    std::string ceapi ceReadString(const std::string ValueName, const std::string Default);
    std::list<std::string> ceapi ceReadMultiString(const std::string ValueName, const std::list<std::string> Default);
    std::string ceapi ceReadExpandString(const std::string ValueName, const std::string Default);
    std::shared_ptr<void> ceapi ceReadBinary(const std::string ValueName, const void * pDefault);
  protected:
  };

  class CERegistryW : public CERegistrySupport {
  private:
    std::wstring m_SubKey;
  public:
    CERegistryW();
    CERegistryW(eRegRoot RegRoot);
    CERegistryW(eRegRoot RegRoot, const std::wstring SubKey);
    virtual ~CERegistryW() {};

    ulong ceapi ceGetSizeOfMultiString(const wchar * lpcwszMultiString);
    ulong ceapi ceGetDataSize(const std::wstring ValueName, ulong ulType);

    bool ceapi ceCreateKey();
    bool ceapi ceCreateKey(const std::wstring SubKey);
    bool ceapi ceKeyExists();
    bool ceapi ceKeyExists(const std::wstring SubKey);
    bool ceapi ceOpenKey(eRegAccess RegAccess = eRegAccess::RA_ALL_ACCESS);
    bool ceapi ceOpenKey(const std::wstring SubKey, eRegAccess RegAccess = eRegAccess::RA_ALL_ACCESS);
    bool ceapi ceDeleteKey();
    bool ceapi ceDeleteKey(const std::wstring SubKey);
    bool ceapi ceDeleteValue(const std::wstring Value);

    std::list<std::wstring> ceapi ceEnumKeys();
    std::list<std::wstring> ceapi ceEnumValues();

    bool ceapi ceWriteInteger(const std::wstring ValueName, int Value);
    bool ceapi ceWriteBool(const std::wstring ValueName, bool Value);
    bool ceapi ceWriteFloat(const std::wstring ValueName, float Value);
    bool ceapi ceWriteString(const std::wstring ValueName, const std::wstring Value);
    bool ceapi ceWriteMultiString(const std::wstring ValueName, const wchar * Value);
    bool ceapi ceWriteMultiString(const std::wstring ValueName, const std::list<std::wstring> Value);
    bool ceapi ceWriteExpandString(const std::wstring ValueName, std::wstring Value);
    bool ceapi ceWriteBinary(const std::wstring ValueName, void * pData, ulong ulSize);

    int ceapi ceReadInteger(const std::wstring ValueName, int Default);
    bool ceapi ceReadBool(const std::wstring ValueName, bool Default);
    float ceapi ceReadFloat(const std::wstring ValueName, float Default);
    std::wstring ceapi ceReadString(const std::wstring ValueName, const std::wstring Default);
    std::list<std::wstring> ceapi ceReadMultiString(const std::wstring ValueName, const std::list<std::wstring> Default);
    std::wstring ceapi ceReadExpandString(const std::wstring ValueName, const std::wstring Default);
    std::shared_ptr<void> ceapi ceReadBinary(const std::wstring ValueName, const void * Default);
  protected:
  };

  /* --- Cat : Critical Section --- */

  class CECriticalSection {
  private: TCriticalSection m_CriticalSection;
  public:
    CECriticalSection() {};
    virtual ~CECriticalSection() {};

    void ceapi ceInit();
    void ceapi ceEnter();
    void ceapi ceLeave();
    void ceapi ceDestroy();

    TCriticalSection& ceapi ceGetCurrentSection();
  protected:
  };

  /* --- Cat : PE File --- */

  typedef struct {
    ulong IIDID;
    std::string Name;
    PImportDescriptor pIID;
  } TExIID, *PExIID;

  typedef struct {
    ulong IIDID;
    std::string Name;
    //ulong NumberOfFuctions;
  } TDLLInfo, *PDLLInfo;

  template<typename T>
  struct TFunctionInfoT {
    ulong IIDID;
    std::string Name;
    T Ordinal;
    ushort Hint;
    T RVA;
  };

  typedef TFunctionInfoT<ulong32> TFunctionInfo32;
  typedef TFunctionInfoT<ulong64> TFunctionInfo64;

  typedef enum _IMPORTED_FUNCTION_FIND_BY {
    IFFM_HINT,
    IFFM_NAME
  } eImportedFunctionFindMethod;

  template <typename T>
  class CEPEFileSupportT {
  public:
    CEPEFileSupportT();
    virtual ~CEPEFileSupportT();

    void* ceapi ceGetpBase();
    TPEHeaderT<T>* ceapi ceGetpPEHeader();

    T ceapi ceRVA2Offset(T RVA);
    ulong ceapi ceOffset2RVA(ulong Offset);

    std::list<PSectionHeader>& ceapi ceGetSetionHeaderList(bool Reget = false);
    std::list<PImportDescriptor>& ceapi ceGetImportDescriptorList(bool Reget = false);
    virtual std::list<TExIID>& ceapi ceGetExIIDList();
    virtual std::list<TDLLInfo> ceapi ceGetDLLInfoList(bool Reget = false);
    virtual std::list<TFunctionInfoT<T>> ceapi ceGetFunctionInfoList(bool Reget = false); // Didn't include import by index
    virtual TDLLInfo ceapi ceFindImportedDLL(const std::string DLLName);
    virtual TFunctionInfoT<T> ceapi ceFindImportedFunction(const std::string FunctionName);
    virtual TFunctionInfoT<T> ceapi ceFindImportedFunction(const ushort FunctionHint);
    virtual TFunctionInfoT<T> ceapi ceFindImportedFunction(
      const TFunctionInfoT<T>& FunctionInfo,
      eImportedFunctionFindMethod Method
    );
  protected:
    bool m_Initialized;

    void* m_pBase;

    TDosHeader* m_pDosHeader;
    TPEHeaderT<T>* m_pPEHeader;

  private:
    T m_OrdinalFlag;

    std::list<PSectionHeader> m_SectionHeaderList;
    std::list<PImportDescriptor> m_ImportDescriptorList;
    std::list<TExIID> m_ExIDDList;
    std::list<TFunctionInfoT<T>> m_FunctionInfoList;
  };

  template <typename T>
  class CEPEFileTA : public CEPEFileSupportT<T> {
  public:
    CEPEFileTA();
    CEPEFileTA(const std::string PEFilePath);
    ~CEPEFileTA();

    CEResult ceapi ceParse(const std::string PEFilePath = "");

  private:
    std::string m_FilePath;
    CEFileMappingA m_FileMap;
  };

   template <typename T>
  class CEPEFileTW : public CEPEFileSupportT<T> {
  public:
    CEPEFileTW();
    CEPEFileTW(const std::wstring PEFilePath);
    ~CEPEFileTW();

    CEResult ceapi ceParse(const std::wstring PEFilePath = L"");

  private:
    std::wstring m_FilePath;
    CEFileMappingW m_FileMap;
  };

  /*--------------------- The definition of common Class(es) which compatible both ANSI & UNICODE --------------------*/

#ifdef _UNICODE
  #define CEDynHook CEDynHookW
  #define CEService CEServiceW
  #define CEFile CEFileW
  #define CELibrary CELibraryW
  #define CEFileMapping CEFileMappingW
  #define CEIniFile CEIniFileW
  #define CERegistry CERegistryW
  #define CEPEFileT CEPEFileTW
#else
  #define CEDynHook CEDynHookA
  #define CEService CEServiceA
  #define CEFile CEFileA
  #define CELibrary CELibraryA
  #define CEFileMapping CEFileMappingA
  #define CEIniFile CEIniFileA
  #define CERegistry CERegistryA
  #define CEPEFileT CEPEFileTA
#endif

} // namespace ce

#endif // CATENGINE_H
