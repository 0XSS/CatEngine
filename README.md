**CatEngine**
========
***
**CatEngine is a C++ library which wrote by me. It helps your programming go easier and faster.**
**Currently, It's available for MSVC/MinGW/C++Builder and only on Windows platform.**

**Infomation**
<i>
- Name:     CatEngine
- Version:  1.0
- Platform: Windows
- Type:     C++ Library for MSVC/MinGW/C++Builder
- Author:   Vic P. aka vic4key
- Mail:     vic4key[at]gmail.com
- Blog:     http://viclab.biz
- Website:  http://cin1team.biz
</i>

**Usage:**

**Note:</u> Firt of all, compile CatEngine library**

 **General Env**
>%CatEngine% = < path\_to\_CatEngine_folder > // <i>that contains CatEngine .h/.cpp</i>

- **for MSVC <u>(Cfg IDE)</u>**

>**Inc**
$(CatEngine)\CatEngine

>**Lib**
$(CatEngine)\$(Platform)\$(Configuration)

>**Src**
\#include "CatEngine.h"
\#pragma comment(lib, "CatEngine.lib")


- **for MinGW <u>(Env)</u>**

>**Inc**
%CPLUS\_INCLUDE\_PATH% = %CatEngine%\CatEngine

>**Lib**
%LIBRARY_PATH% = %CatEngine%\CatEngine

>**Src**
\#include "CatEngine.h"

>**Cmd**
>Eg: G++ your\_program.cpp --std=c++11 -lCatEngine -lws2_32 -o your\_program.exe

- **for C++ Builder<u></u>**

><<i>I'll update later. I've no more free time now</i>>