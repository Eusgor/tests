import os


def func_search (filename, funcname, dfile, func_count):
    with open(filename) as file:
        str_num = 0
        for line in file:
            str_num += 1
            if (line.startswith(funcname) 
                and (line[len(funcname)] == "("
                or line[len(funcname)] == " ")):
                dfile[funcname] = [filename, str_num, func_count]
                return 1
    return 0

raw = {}
with open("rawfile") as rawfile:
    i = 0
    for line in rawfile:
        i += 1
        sline = line.split(",")
        key = sline[0]
        try:
            val = int(sline[1])
        except:
            continue
        raw[key] = raw.get(key, 0) + val
        
with open("raw_sort", "w") as sraw:
    for k, v in raw.items():
        sraw.write(k + "," + str(v) + "\n")
        
del raw

os.system("addr2line -fp -e /usr/lib/debug/boot/kernel/kernel.debug < raw_sort > trace")

cov = open("coverage", "w")

dfiles = {}
with open("nmlines") as nmlines:
    for line in nmlines:
        sline = line.split()
        if len(sline) < 5:
            continue
        if sline[1] != "t" and sline[1] != "T":
            continue
        dfiles[sline[0]] = [sline[4].split(":")[0], int(sline[4].split(":")[1])]
        dfiles[sline[0]].append(0)
        cov.write("SF:" + sline[4].split(":")[0] + "\n")
        cov.write("FN:" + sline[4].split(":")[1] + "," + sline[0] + "\n")
        cov.write("FNDA:0," + sline[0] + "\n")
        cov.write("DA:" + sline[4].split(":")[1] + ",0\n")
        cov.write("end_of_record\n")

trace_arr = []
with open("trace") as trace:
    for line in trace:
        trace_arr.append(line)

with open("raw_sort") as sraw:
    i = 0
    for line in sraw:
        sline = line[:-1].split(",")
        trace_arr[i] = trace_arr[i][:-1] + " " + sline[1]
        i += 1

os.remove("raw_sort")

for mem in trace_arr:
    if mem[0] == "?":
        continue
    sline = mem.split()
    func_name = sline[0]
    func_addr = sline[2].split(":")[0]
    str_num = int(sline[2].split(":")[1])
    func_count = int(sline[3])
    cov.write("SF:" + func_addr + "\n")
    if dfiles.get(func_name) == None:
        ret = func_search(func_addr, func_name, dfiles, func_count)
        if not ret:
            cov.write("end_of_record\n")
            continue
        else:
            cov.write("FN:" + str(dfiles[func_name][1]) + "," + func_name + "\n")
    if func_addr != dfiles[func_name][0]:
        if str_num != 0:
            cov.write("DA:" + str(str_num) + "," + str(func_count) + "\n")
        cov.write("end_of_record\n")
        continue
    cov.write("FNDA:" + str(func_count) + "," + func_name + "\n")
    if str_num == 0:
        cov.write("DA:" + str(dfiles[func_name][1]) + "," + str(func_count) + "\n")
    else:
        cov.write("DA:" + str(dfiles[func_name][1]) + "," + str(func_count) + "\n")
        cov.write("DA:" + str(str_num) + "," + str(func_count) + "\n")
    cov.write("end_of_record\n")
    
cov.close()
print("Done")


