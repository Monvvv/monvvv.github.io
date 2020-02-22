---
layout: article
title: 某LuaJIT游戏的Anti-Cheat分析
lang: zh
license: CC-BY-NC-4.0
aside:
  toc: true
---

# 前言

这个游戏防修改的方法很平常，但因为是用`LuaJIT`写的引擎，所以不是太直观。所以与其说文章是关于游戏修改，倒不如说是在介绍LuaJIT。另外，由于这游戏有充值系统，所以省略了游戏有关的具体信息。

# 第一次尝试

打开游戏，随便找一个比较大的数值，打开CE，搜索数值，发现能够搜索到。
![image-1](\assets\2020-02-20-Bypass-A-Games-Anti-Cheat\image-1.png)
![image-2](\assets\2020-02-20-Bypass-A-Games-Anti-Cheat\image-2.png)
然后修改之，然后游戏就喜闻乐见的闪退了。

# 分析

重新打开游戏，搜索数值，在数据上按`F5`(或右键单击->`Find out what acess this address`)，能看到有好几条指令在持续不断的访问。
![image-3](\assets\2020-02-20-Bypass-A-Games-Anti-Cheat\image-3.png)
点击`Show disassembler`，能看到这几条指令都是属于一个名为`LScript.dll`的DLL文件的。而通过DLL导出的符号可以猜到其是`LuaJIT`库。
![image-4](\assets\2020-02-20-Bypass-A-Games-Anti-Cheat\image-4.png)
![image-5](\assets\2020-02-20-Bypass-A-Games-Anti-Cheat\image-5.png)

## Dump & Inject

于是乎，我们直接将游戏的脚本直接用OD载入，在DLL被载入后输入`bp luaL_loadbuffer`。该函数声明为：

```c
int luaL_loadbuffer(lua_State*L,const char*buff,size_t size,const char*name)
```

然后通过hook这里，我们就可以将游戏脚本dump出来，将自己的代码注入到游戏里。比如：

```c
// create hook
int luaL_loadbuffer_new(lua_State*L,const char*buff,size_t size,const char*name) {
    luaL_dofile(l, filename);
    Dump(name, buff, size);
    // call original
}
```
将脚本Dump出来后，基本可以断定游戏的主要逻辑都写在`lua`里，于是注入自己的脚本：
```lua
-- 由于游戏检测到修改后的应对方式是退出，我们可以尝试hook os.exit
local ffi = require("ffi")
local debug = require("debug")
ffi.cdef[[
    void OutputDebugStringA(const char* lpDebugString);
]]
os.exit = function ()
    -- 打印os.exit的调用栈
    ffi.C.OutputDebugStringA(debug.traceback())
    -- call os_exit_original
end
```

打开游戏随便修改一下数据，打印出的内容如下(我删掉了一些信息)：

```
 stack traceback:
  fuck.lua:10: in function 'Osexit'
  pm.lua:216: in function 'exit'
  sys.lua:19233: in function 'run'
  sys.lua:20363: in function '__index'
  da.lua:8192: in function '材料显示'
  da.lua:3023: in function 'cfun'
  sys.lua:14846: in function 'run'
  [C]: in function 'xpcall'
```

重点在`__index`这一行，`__index`是一个`metamethod `(元方法)，当读取一个table的键值时被调用，所以大抵的检测逻辑可能为：

```lua
function fk_ce(data)
    local mt = {
        __index = function (t, k)
            if is_cheated(data[k]) then
                run(os.exit)
            end
        end
    }
    setmetetable(data, mt)
end
```

## Bytecode

目前解析`LuaJIT Bytecode`的工具有三个，分别为：

- luajit自带一个解析命令(-bl)
- luajit-lang-toolkit(-bx)
- ljd(反编译，不过不再维护，很多bug)

这里使用`luajit-lang-toolkit`来解析dump出的Lua文件。

```bash
$ cd luajit-lang-toolkit
$ luajit run.lua -bx sys.lua > sys.txt
```

然后找到`__index`的实现：

```
2b 02 00 00             | 0001    UGET     2   0      ; self
37 02 00 02             | 0002    TGETS    2   2   0  ; "__p"
36 02 01 02             | 0003    TGETV    2   2   1
0a 02 00 00             | 0004    ISEQP    2   0
54 02 2a 80             | 0005    JMP      2 => 0048
34 02 01 00             | 0006    GGET     2   1      ; "type"
2b 03 00 00             | 0007    UGET     3   0      ; self
37 03 02 03             | 0008    TGETS    3   3   2  ; "__数据"
36 03 01 03             | 0009    TGETV    3   3   1
3e 02 02 02             | 0010    CALL     2   2   2
07 02 03 00             | 0011    ISNES    2   3      ; "table"
54 02 04 80             | 0012    JMP      2 => 0017
2b 02 00 00             | 0013    UGET     2   0      ; self
37 02 02 02             | 0014    TGETS    2   2   2  ; "__数据"
36 02 01 02             | 0015    TGETV    2   2   1
48 02 02 00             | 0016    RET1     2   2
34 02 04 00             | 0017 => GGET     2   4      ; "string"
37 02 05 02             | 0018    TGETS    2   2   5  ; "reverse"
34 03 06 00             | 0019    GGET     3   6      ; "tostring"
2b 04 00 00             | 0020    UGET     4   0      ; self
37 04 02 04             | 0021    TGETS    4   4   2  ; "__数据"
36 04 01 04             | 0022    TGETV    4   4   1
3e 03 02 00             | 0023    CALL     3   0   2
3d 02 00 02             | 0024    CALLM    2   2   0
2b 03 00 00             | 0025    UGET     3   0      ; self
37 03 00 03             | 0026    TGETS    3   3   0  ; "__p"
36 03 01 03             | 0027    TGETV    3   3   1
04 02 03 00             | 0028    ISEQV    2   3
54 02 12 80             | 0029    JMP      2 => 0048
34 02 07 00             | 0030    GGET     2   7      ; "Sys"
37 02 08 02             | 0031    TGETS    2   2   8  ; "run"
25 03 09 00             | 0032    KSTR     3   9      ; "debug_msg"
27 04 01 00             | 0033    KSHORT   4   1
32 05 04 00             | 0034    TNEW     5   4
3b 01 01 05             | 0035    TSETB    1   5   1
2b 06 00 00             | 0036    UGET     6   0      ; self
37 06 02 06             | 0037    TGETS    6   6   2  ; "__数据"
36 06 01 06             | 0038    TGETV    6   6   1
3b 06 02 05             | 0039    TSETB    6   5   2
34 06 04 00             | 0040    GGET     6   4      ; "string"
37 06 05 06             | 0041    TGETS    6   6   5  ; "reverse"
2b 07 00 00             | 0042    UGET     7   0      ; self
37 07 00 07             | 0043    TGETS    7   7   0  ; "__p"
36 07 01 07             | 0044    TGETV    7   7   1
3e 06 02 00             | 0045    CALL     6   0   2
3c 06 00 00             | 0046    TSETM    6   0      ; 4.5035996273705e
                        | +15
3e 02 04 01             | 0047    CALL     2   1   4
2b 02 00 00             | 0048 => UGET     2   0      ; self
37 02 02 02             | 0049    TGETS    2   2   2  ; "__数据"
36 02 01 02             | 0050    TGETV    2   2   1
48 02 02 00             | 0051    RET1     2   2
                        | .. uv ..
02 c0                   | upvalue local 2
                        | .. kgc ..
0e 64 65 62 75 67 5f 6d | kgc: "debug_msg"
73 67                   | 
08 72 75 6e             | kgc: "run"
08 53 79 73             | kgc: "Sys"
0d 74 6f 73 74 72 69 6e | kgc: "tostring"
67                      | 
0c 72 65 76 65 72 73 65 | kgc: "reverse"
0b 73 74 72 69 6e 67    | kgc: "string"
0a 74 61 62 6c 65       | kgc: "table"
0b 5f 5f ca fd be dd    | kgc: "__数据"
09 74 79 70 65          | kgc: "type"
08 5f 5f 70             | kgc: "__p"
                        | .. knum ..
07 80 80 c0 99 04       | knum num: 4.5036e+15
73 65 6c 66 00          | uv0: name: self
```
LuaJIT的bytecode设计很简洁，将其转为Lua源码也不难，或者直接使用`ljd`进行反编译也可行，下面是等价的更易读的Lua代码：
```lua
function __index(t, k)
    if self.__p[k] ~= nil and type(self.__数据[k]) ~= "table" then
        if string.reverse(tostring(self.__数据[k])) ~= self.__p[k] then
            -- 保存信息，退出
        end
    else
        return self.__数据[k]
    end
end
```
# 问题

根据上面的实现很容易能看出，要绕过判断只要把对应的table`__p`内的数据也修改掉就可以。但事实上，并非这样。

为了说明，打开LuaJIT，输入以下代码：

```lua
a = "1234567"
b = "7654321"
print(a, b, a == b)
-- output:
-- 1234567 7654321 false
```

然后打开CE，将b的值改为"1234567"，结果输出如下：

```lua
-- output:
-- 1234567 1234567 false
```

这和LuaJIT内`==`所采用的方法有关：

```c
/* lj_obj */

/* GCobj reference */
typedef struct GCRef {
  uint32_t gcptr32;	/* Pseudo 32 bit pointer. */
} GCRef;

typedef LJ_ALIGN(8) union TValue {
  GCRef gcr;	/* GCobj reference (if any). */
}
typedef const TValue cTValue;

/* Compare two objects without calling metamethods. */
int lj_obj_equal(cTValue *o1, cTValue *o2)
{
  if (itype(o1) == itype(o2)) {
    if (tvispri(o1))
      return 1;
    if (!tvisnum(o1))
      return gcrefeq(o1->gcr, o2->gcr);
  } else if (!tvisnumber(o1) || !tvisnumber(o2)) {
    return 0;
  }
  return numberVnum(o1) == numberVnum(o2);
}
```

字符串在LuaJIT内的结构为：

```c
/* String object header. String payload follows. */
typedef struct GCstr {
  GCHeader;
  uint8_t reserved;	/* Used by lexer for fast lookup of reserved words. */
  uint8_t unused;
  MSize hash;		/* Hash of string. */
  MSize len;		/* Size of string. */
  char str[len];    /* 我自己加的，实际是用的宏 */
} GCstr;
#define strdata(s)	((const char *)((s)+1))
```

所以即使修改了字符串值，但由于字符串是否相等是通过引用对比而非值对比确定的，`a == b`依然为`false`。

# 结束

想要解决这个问题也很简单，只要将`b`的引用修改为`a`的引用，或者直接通过注入的Lua脚本修改(比如将Bytecode第4行的ISEQP删除掉)。

## 测试

搜索`b_str_address - 0x16(sizeof GCstr)`然后将指针改为`b_str_address - 0x16`，输出：`1234567 1234567 true`。

而在游戏内，可以通过将`__p`内的引用改为其他数据的引用来实现将一个数据修改为另一个已存在的数据(0x11327F90内的数据是原先`__p`内的字符串，由于缺少了引用被GC删除了)。
![image-6](\assets\2020-02-20-Bypass-A-Games-Anti-Cheat\image-6.png)
![image-7](\assets\2020-02-20-Bypass-A-Games-Anti-Cheat\image-7.png)

# 参考

1. [Lua Source](https://www.lua.org/source/5.1/).
2. [Lua Manual Metatables](https://www.lua.org/manual/5.1/manual.html#2.8)
3. [LuaJIT 2.0.4 Source](http://luajit.org/download.html)
4. [LuaJIT bytecode](http://wiki.luajit.org/Bytecode-2.0)
5. [luajit-lang-toolkit](https://github.com/franko/luajit-lang-toolkit)
6. [ljd](https://github.com/NightNord/ljd)