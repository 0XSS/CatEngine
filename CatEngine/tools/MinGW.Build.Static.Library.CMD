@ECHO OFF
SET NAME=CatEngine
G++ -c --std=c++11 -lws2_32 ../src/%NAME%.cpp -o %NAME%.o
AR rcs ../lib/lib%NAME%.a %NAME%.o
DEL %NAME%.o
PAUSE