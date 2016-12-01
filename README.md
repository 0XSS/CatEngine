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
- Type:     C&#43;&#43; Library for MSVC/MinGW/C&#43;&#43;Builder
- Author:   Vic P. aka vic4key
- Mail:     vic4key[at]gmail.com
- Blog:     http://viclab.biz
- Website:  http://cin1team.biz
</i>

**Usage:**

**Note:</u> Firt of all, compile CatEngine library**

 **General Env**
>%CatEngine% = &lt;path\_to\_CatEngine-master_folder&gt; // <i>that contains CatEngine folder</i>

- **for MSVC <u>(Cfg IDE)</u>**

>**Inc**
$(CatEngine)\CatEngine

>**Lib**
$(CatEngine)\$(Platform)\$(Configuration)

>**Src**
\#include &lt;CatEngine.h&gt;
\#pragma comment(lib, "CatEngine.lib")


- **for MinGW <u>(Env)</u>**

>**Inc**
%CPLUS\_INCLUDE\_PATH% = %CatEngine%\CatEngine

>**Lib**
%LIBRARY_PATH% = %CatEngine%\CatEngine

>**Src**
\#include &lt;CatEngine.h&gt;

>**Cmd**
>Eg: G&#43;&#43; your\_program.cpp &#45;o your\_program.exe &#45;&#45;std=c++11 &#45;lCatEngine &#45;lws2_32

- **for C++ Builder<u></u>**

><<i>Sorry. I haven't checked yet and update it later. I've no C++ Builder compiler and no more free time now.</i>>