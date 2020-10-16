# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

import unicorn
import random
import string
import capstone
import re
import globalData
import binascii

def ranstr(num):
    salt = ''.join(random.sample(string.ascii_letters + string.digits, num))
    return salt

cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
cs.detail = True
all_regs = None
reg_names = {
    "X0": unicorn.arm64_const.UC_ARM64_REG_X0,
    "X1": unicorn.arm64_const.UC_ARM64_REG_X1,
    "X2": unicorn.arm64_const.UC_ARM64_REG_X2,
    "X3": unicorn.arm64_const.UC_ARM64_REG_X3,
    "X4": unicorn.arm64_const.UC_ARM64_REG_X4,
    "X5": unicorn.arm64_const.UC_ARM64_REG_X5,
    "X6": unicorn.arm64_const.UC_ARM64_REG_X6,
    "X7": unicorn.arm64_const.UC_ARM64_REG_X7,
    "X8": unicorn.arm64_const.UC_ARM64_REG_X8,
    "X9": unicorn.arm64_const.UC_ARM64_REG_X9,
    "X10": unicorn.arm64_const.UC_ARM64_REG_X10,
    "X11": unicorn.arm64_const.UC_ARM64_REG_X11,
    "X12": unicorn.arm64_const.UC_ARM64_REG_X12,
    "X13": unicorn.arm64_const.UC_ARM64_REG_X13,
    "X14": unicorn.arm64_const.UC_ARM64_REG_X14,
    "X15": unicorn.arm64_const.UC_ARM64_REG_X15,
    "X16": unicorn.arm64_const.UC_ARM64_REG_X16,
    "X17": unicorn.arm64_const.UC_ARM64_REG_X17,
    "X18": unicorn.arm64_const.UC_ARM64_REG_X18,
    "X19": unicorn.arm64_const.UC_ARM64_REG_X19,
    "X20": unicorn.arm64_const.UC_ARM64_REG_X20,
    "X21": unicorn.arm64_const.UC_ARM64_REG_X21,
    "X22": unicorn.arm64_const.UC_ARM64_REG_X22,
    "X23": unicorn.arm64_const.UC_ARM64_REG_X23,
    "X24": unicorn.arm64_const.UC_ARM64_REG_X24,
    "X25": unicorn.arm64_const.UC_ARM64_REG_X25,
    "X26": unicorn.arm64_const.UC_ARM64_REG_X26,
    "X27": unicorn.arm64_const.UC_ARM64_REG_X27,
    "X28": unicorn.arm64_const.UC_ARM64_REG_X28,
    "W0": unicorn.arm64_const.UC_ARM64_REG_W0,
    "W1": unicorn.arm64_const.UC_ARM64_REG_W1,
    "W2": unicorn.arm64_const.UC_ARM64_REG_W2,
    "W3": unicorn.arm64_const.UC_ARM64_REG_W3,
    "W4": unicorn.arm64_const.UC_ARM64_REG_W4,
    "W5": unicorn.arm64_const.UC_ARM64_REG_W5,
    "W6": unicorn.arm64_const.UC_ARM64_REG_W6,
    "W7": unicorn.arm64_const.UC_ARM64_REG_W7,
    "W8": unicorn.arm64_const.UC_ARM64_REG_W8,
    "W9": unicorn.arm64_const.UC_ARM64_REG_W9,
    "W10": unicorn.arm64_const.UC_ARM64_REG_W10,
    "W11": unicorn.arm64_const.UC_ARM64_REG_W11,
    "W12": unicorn.arm64_const.UC_ARM64_REG_W12,
    "W13": unicorn.arm64_const.UC_ARM64_REG_W13,
    "W14": unicorn.arm64_const.UC_ARM64_REG_W14,
    "W15": unicorn.arm64_const.UC_ARM64_REG_W15,
    "W16": unicorn.arm64_const.UC_ARM64_REG_W16,
    "W17": unicorn.arm64_const.UC_ARM64_REG_W17,
    "W18": unicorn.arm64_const.UC_ARM64_REG_W18,
    "W19": unicorn.arm64_const.UC_ARM64_REG_W19,
    "W20": unicorn.arm64_const.UC_ARM64_REG_W20,
    "W21": unicorn.arm64_const.UC_ARM64_REG_W21,
    "W22": unicorn.arm64_const.UC_ARM64_REG_W22,
    "W23": unicorn.arm64_const.UC_ARM64_REG_W23,
    "W24": unicorn.arm64_const.UC_ARM64_REG_W24,
    "W25": unicorn.arm64_const.UC_ARM64_REG_W25,
    "W26": unicorn.arm64_const.UC_ARM64_REG_W26,
    "W27": unicorn.arm64_const.UC_ARM64_REG_W27,
    "W28": unicorn.arm64_const.UC_ARM64_REG_W28,
    "SP": unicorn.arm64_const.UC_ARM64_REG_SP,
}

#初始化全局数据
def initGlobalData():
    globalData.has_pre=False
    globalData.pre_codestr=""
    globalData.pre_regname=""
    #添加监视列表,trace时打印该内存的变动
    globalData.watch_addrs= {0x7eae07e060:""}


def hook_code(uc: unicorn.Uc, address, size, user_data):
    inst_code=uc.mem_read(address,size)
    for inst in cs.disasm(inst_code,size):
        #判断是否保存有上次的指令，有的话，则先打印上次的指令，并且查询上次的第一个寄存器的新数值
        if globalData.has_pre and globalData.pre_regname:
            regindex = reg_names[globalData.pre_regname.upper()]
            regvalue = uc.reg_read(regindex)
            globalData.pre_codestr+="\t//%s=0x%x" % (globalData.pre_regname,regvalue)
            print(globalData.pre_codestr)
            globalData.pre_codestr=""
            globalData.has_pre=False

        #监控我关心的内存空间，如果发生变动会再打印
        if len(globalData.watch_addrs)>0:
            for i,v in globalData.watch_addrs.items():
                idata= uc.mem_read(i,0x10)
                buf= binascii.b2a_hex(idata)
                hexstr=buf.decode(encoding="utf-8")
                if globalData.watch_addrs[i]==hexstr:
                    continue
                globalData.watch_addrs[i]=hexstr
                print("0x%x\t%s" % (i, hexstr))

        #拼接当前行的汇编指令
        opstr="0x%x:\t%s\t%s" % (address, inst.mnemonic, inst.op_str)
        #从当前行指令中匹配出所有的寄存器
        res = re.findall(r'[^0]([wx][0-9]+)', " " + inst.op_str, re.I | re.M)
        #如果有多个寄存器，取第一个为数值被改变的寄存器
        if len(res)>0:
            globalData.pre_regname = res[0]
        res=list(set(res))
        #如果有sp寄存器，则单独插入
        if "sp" in inst.op_str:
            res.append("sp")
        #如果没有寄存器，则不需要记录为上次的，直接打印即可
        if len(res)<=0:
            has_pre=False
            print(opstr)
            continue
        #记录数据为上次的指令
        fenge = "\t\t------"
        curreg=""
        for regname in res:
            regindex=reg_names[regname.upper()]
            regvalue=uc.reg_read(regindex)
            curreg+="%s=0x%x\t" % (regname,regvalue)
        globalData.pre_codestr=opstr +fenge+ curreg
        globalData.has_pre=True


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    initGlobalData()
    #创建uc对象
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM)
    #从内存中dump下来so的基址
    code_addr=0x7eae047000
    #用来存放so代码的大小，尽量大一点。内存不值钱
    code_size=8*0x1000*0x1000
    #创建一块内存
    uc.mem_map(code_addr,code_size)
    #在上面那块内存后面继续划一片内存来当做栈空间
    stack_addr=code_addr+code_size
    stack_size=0x1000
    #栈顶的位置，这里是64位的，所以偏移8个字节
    stack_top=stack_addr+stack_size-0x8
    #申请一块栈空间
    uc.mem_map(stack_addr,stack_size)
    #栈空间往后继续划一块空间用来存放参数
    args_addr=stack_addr+stack_size
    args_size=0x1000
    uc.mem_map(args_addr, args_size)
    #设置每句汇编执行都会调用hook_code
    uc.hook_add(unicorn.UC_HOOK_CODE,hook_code)
    #读取so
    with open("./libnative-lib.so_0x7eae047000_0x38000.so","rb") as f:
        sodata=f.read()
        #给前面创建的空间写入so的数据
        uc.mem_write(code_addr,sodata)
        #要执行的代码开始位置
        start_addr=code_addr+0xFCB4
        #要执行的代码结束位置
        end_addr=code_addr+0xFF2C
        #随机生成一个入参
        input_str = ranstr(36)
        print("input:%s input_addr:0x%x" % (input_str,args_addr))
        input_byte=str.encode(input_str)
        #将生成的入参写入前面创建的内存空间
        uc.mem_write(args_addr,input_byte)
        #ida中看到的函数有参数1、2，然后分别对应X0和X1，写入对应数据，栈寄存器给一个栈顶的地址
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0,args_addr)
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_X1,len(input_str))
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP,stack_top)
        #开始执行代码段
        uc.emu_start(start_addr,end_addr)
        #ida中看到返回值是直接写在入参中，所以结果我们直接从入参的内存中读取
        result=uc.mem_read(args_addr,args_size)
        print("result:",result.decode(encoding="utf-8"))
    #最后释放创建的内存
    uc.mem_unmap(args_addr, args_size)
    uc.mem_unmap(stack_addr,stack_size)
    uc.mem_unmap(code_addr,code_size)


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
