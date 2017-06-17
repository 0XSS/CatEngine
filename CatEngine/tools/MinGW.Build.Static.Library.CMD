@ECHO OFF
SET NAME=CatEngine
SET LIB=..\lib
IF NOT EXIST %LIB% MKDIR %LIB%
G++ -c --std=c++11 -lws2_32 ..\src\%NAME%.cpp -o %NAME%.o
AR rcs %LIB%\lib%NAME%.a %NAME%.o
DEL %NAME%.o
PAUSE