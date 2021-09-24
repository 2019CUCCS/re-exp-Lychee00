import re
address=[]
flag=0
num=0

# 获取每个函数的地址
with open(r'ping_disasm.txt','r') as f:
    lines = f.readlines()
    for line in lines:
        if 'call' in line:
            pattern = re.compile(r'call        ([\dA-F]{8})')
            ad = re.search(pattern,line)
            if ad:
                address.append(ad.group(1))
    addr = list(set(address)) #去重
    addr.remove('00403825') # 除去main函数

    print('序号|函数起始地址|')
    for index,add in enumerate(addr):
        num+=1
        print(str(index+1)+':'+add)
    print('函数总数为：'+str(num))

# 将每个函数的汇编指令单独保存成一个文本文件
for name in addr:
    output = open('./func/'+name+'.txt','w')
    pattern = re.compile(name+':')
    with open(r'ping_disasm.txt','r') as f:  
        lines = f.readlines()
        for line in lines:
            head = re.findall(pattern, line)
            if head:
                flag=1  
            if flag:   
                output.write(line) 
                toe = re.findall('ret',line)
                if toe or '004039FB' in line: # 判断是否有函数结束的标志ret，或是进程是否结束
                    flag=0
                    break
                else:
                    continue
            else:
                continue
    output.close()
