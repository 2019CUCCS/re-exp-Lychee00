# 逆向工程实验二
## 实验要求
- 找出一个exe文件中有多少个函数，并且知道这些函数的位置：
- 已知，vs的dumpbin工具，可以获得一个exe文件的全部反汇编指令（/disasm）,Linux下的Objdump可以实现类似功能。编写一段程序（python），获得一个exe文件中有多少个函数，以及每个函数的地址？
- 将每个函数的汇编指令，单独保持为一个文本文件。
    - 注意main函数（在dumpbin /headers 命令的结果中，可以看到EntryPoint）。

## 实验步骤
### 1.导出PING.EXE的反汇编文件```ping_disasm.txt```
```asm
dumpbin /disasm C:\Windows\SysWOW64\PING.EXE >D:\ping_disasm.txt
```
### 2.找到main函数的位置
- Linux系统下```objdump -f```显示文件头信息：
```bash
objdump -f PING.EXE
```
- 结果如下,即```PING.EXE```的 EntryPoint 为：0x00403450
```asm

PING.EXE:	file format COFF-i386

architecture: i386
start address: 0x00403450
```
- 在```ping_disasm.txt```中找到地址对应的指令，即main函数开始地址为00403825
```
00403450: E8 D0 03 00 00     call        00403825
00403455: E9 D9 FD FF FF     jmp         00403233
```
- 随后的统计与分离过程应刨去该地址。

### 3.获取该文件中共有几个函数，及每个函数的地址
- 除了入口函数（main）和回调函数之外，所有函数都会被调用，如果不被调用，这个函数在编译阶段就会被排除在外
- 一个函数的地址必然出现在这一段汇编指令的某条或者某几条call指令之后。
- 本实验中统计的函数被调用的形式为 ```call  xxxxxxxx```,对于```call      dword ptr ds:[xxxxxxxxh]```不考虑在内。
- 获取每个函数的地址
```python
with open(r'ping_disasm.txt','r') as f:
    lines = f.readlines()
    for line in lines:
        if 'call' in line:
            pattern = re.compile(r'call        ([\dA-F]{8})') # 寻找call
            ad = re.search(pattern,line)
            if ad:
                address.append(ad.group(1))
    addr = list(set(address)) #去重

```
- main函数不统计在内
```python
# 除去main函数
    addr.remove('00403825') 
```
- 获取该文件中函数总数
  - 经统计，共有38个函数

```python
    print('序号|函数起始地址|')
    for index,add in enumerate(addr):
        num+=1
        print(str(index+1)+':'+add)
    print('函数总数为：'+str(num))
```
### 4.将每个函数的汇编指令单独保存成一个文本文件

```python
flag = 0
for name in addr:
    output = open('./func/'+name+'.txt','w')
    pattern = re.compile(name+':')
    with open(r'ping_disasm.txt','r') as f:  
        lines = f.readlines()
        for line in lines:
            head = re.findall(pattern, line) # 找到函数开始的地址
            if head:
                flag=1  
            if flag:   
                output.write(line) # 逐指令写入文本文件
                toe = re.findall('ret',line) # 找到函数结束的地址
                if toe or '004039FB' in line: # 如果找到函数结束标志，或是到文件的最后一条指令尚未找到函数结束的标志，则结束写入
                    flag=0
                    break
                else:
                    continue
            else:
                continue
    output.close()
```
- [完整脚本](pd.py)