import sys
import os
from clang.cindex import Index, CursorKind, Config
import json
import subprocess
import re

from clang import cindex

cindex.Config.set_library_file('/mnt/sdb/oss-fuzz/aflgo/instrument/llvm_tools/build/lib/libclang.so.11')

index = cindex.Index.create()
print("libclang loaded successfully")


# 如果需要，设置 libclang 路径，例如：
# Config.set_library_file("/usr/lib/llvm-15/lib/libclang.so")

project_root = "/mnt/sdb/oss-fuzz/arvo/ARVO-Meta/scripts/libxml2/"   # 修改成你项目路径
entry_files = []               # 如果想指定文件，可以填入列表
compile_db_path = os.path.join(project_root, "compile_commands.json")

patch_func = "xmlSAX2CDataBlock"
call_stack_str = '''#0 0x54a372 in xmlParserPrintFileContextInternal /src/libxml2/error.c:201:24
    #1 0x55312c in xmlReportError /src/libxml2/error.c:406:9
    #2 0x54cc89 in __xmlRaiseError /src/libxml2/error.c:633:2
    #3 0x56b2f4 in xmlFatalErrMsg /src/libxml2/parser.c:574:5
    #4 0x5eaf2e in xmlParseDocument /src/libxml2/parser.c:10949:2
    #5 0x614047 in xmlDoRead /src/libxml2/parser.c:15432:5
    #6 0x614742 in xmlReadMemory /src/libxml2/parser.c:15518:13
    #7 0x498c61 in LLVMFuzzerTestOneInput /src/libxml2_xml_read_memory_fuzzer.cc:31:20
    #8 0x4d8939 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:451:13
    #9 0x4d9572 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:408:3
    #10 0x49c73e in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/libfuzzer/FuzzerDriver.cpp:268:6
    #11 0x4aaf7d in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/libfuzzer/FuzzerDriver.cpp:620:9
    #12 0x49b881 in main /src/libfuzzer/FuzzerMain.cpp:20:10
    #13 0x75eb3e1dd82f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #14 0x41f298 in _start (/out/libxml2_xml_read_memory_fuzzer+0x41f298)
    #0 0x44e1d0 in malloc /src/llvm/projects/compiler-rt/lib/msan/msan_interceptors.cc:953
    #1 0x846e3d in xmlBufCreate /src/libxml2/buf.c:137:32
    #2 0x9da702 in xmlSwitchInputEncodingInt /src/libxml2/parserInternals.c:1211:34
    #3 0x9d97e9 in xmlSwitchToEncodingInt /src/libxml2/parserInternals.c:1287:12
    #4 0x9d8bf3 in xmlSwitchEncoding /src/libxml2/parserInternals.c:1107:11
    #5 0x5e9374 in xmlParseDocument /src/libxml2/parser.c:10858:6
    #6 0x614047 in xmlDoRead /src/libxml2/parser.c:15432:5
    #7 0x614742 in xmlReadMemory /src/libxml2/parser.c:15518:13
    #8 0x498c61 in LLVMFuzzerTestOneInput /src/libxml2_xml_read_memory_fuzzer.cc:31:20
    #9 0x4d8939 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:451:13
    #10 0x4d9572 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:408:3
    #11 0x49c73e in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/libfuzzer/FuzzerDriver.cpp:268:6
    #12 0x4aaf7d in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/libfuzzer/FuzzerDriver.cpp:620:9
    #13 0x49b881 in main /src/libfuzzer/FuzzerMain.cpp:20:10
    #14 0x75eb3e1dd82f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)'''



# 递归遍历目录，收集所有 .c/.cc/.cpp 文件
def collect_source_files(root):
    files = []
    for dirpath, _, filenames in os.walk(root):
        for f in filenames:
            if f.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")):
                files.append(os.path.join(dirpath, f))
    return files

# 建立函数调用关系，key: caller, value: set(callees)
callgraph = {}

def visit(node, current_function=None):
    if node.kind == CursorKind.FUNCTION_DECL or node.kind == CursorKind.CXX_METHOD:
        current_function = node.spelling
        if current_function not in callgraph:
            callgraph[current_function] = set()
    elif node.kind == CursorKind.CALL_EXPR and current_function:
        callee = node.displayname.split('(')[0]  # 获取调用函数名
        callgraph.setdefault(current_function, set()).add(callee)
    for c in node.get_children():
        visit(c, current_function)

include_root = os.path.join(project_root, "include")
include_dirs = []

if os.path.isdir(include_root):
    # include_root 本身优先
    include_dirs.append(include_root)
    # 所有子目录
    for dirpath, dirnames, filenames in os.walk(include_root):
        include_dirs.append(dirpath)
else:
    print(f"[warn] include_root 不存在: {include_root}")

# 去重并排序（可选）
include_dirs = sorted(set(include_dirs))

fallback_clang_args = ["-I" + project_root]+["-I" + inc for inc in include_dirs]

# clang_args = ["-I" + project_root]+["-I" + inc for inc in include_dirs]


# print(clang_args)
def analyze_call_stack(call_stack_str):
    call_stack = [line.split(" in ")[-1].split("/src")[0].split(" (")[0].strip() for line in call_stack_str.split('\n')]
    return call_stack

def _strip_next_arg(i, args):
    """用于过滤 '-o foo.o' 这类二元参数；返回新的 index。"""
    if i + 1 < len(args):
        return i + 2  # 跳过当前和下一个
    return i + 1

def prepare_args(raw_args, directory):
    """
    清洗 compile_commands 中的 arguments：
      - 去掉编译器本身 (/usr/bin/gcc)
      - 去掉 -c, -o <out>, -M*, -MD, -MP 等
      - 把相对路径型的 -I.、-I./include 展开成绝对路径
      - 忽略源文件参数（clang.cindex 会自己知道当前 parse() 的源文件）
    返回清洗后的 args 列表。
    """
    cleaned = []
    skip_next = False

    # 常见需要忽略掉的 flag（单独参数形式）
    drop_flags = {"-c", "-S", "-E", "-M", "-MM", "-MG", "-MP", "-MD", "-MMD"}
    # 带值的（后跟1个参数）常见 flag
    drop_with_arg = {"-o", "-MF", "-MT", "-MQ"}

    for i, a in enumerate(raw_args):
        if skip_next:
            skip_next = False
            continue

        # 第一个参数往往是编译器，可直接跳过
        if i == 0 and os.path.basename(a) in ("gcc", "clang", "cc", "g++", "clang++"):
            continue

        # 明确丢弃
        if a in drop_flags:
            continue
        if a in drop_with_arg:
            skip_next = True
            continue

        # 依赖文件生成：-MFfoo.d 这种贴一起写的，粗略清理
        if a.startswith("-MF") and len(a) > 3:
            continue

        # 预处理依赖族：-M* 直接跳
        if a.startswith("-M") and a not in ("-march",):  # 粗略过滤，避免误杀 -march
            # 如果你需要支持 -march=native，自行扩展
            continue

        # 可能是 -Ixxx 或 -I xxx
        if a == "-I":
            # 等待下一个参数作为 include
            skip_next = True
            continue
        if a.startswith("-I"):
            inc = a[2:]
            # 相对路径处理
            if not os.path.isabs(inc):
                inc = os.path.normpath(os.path.join(directory, inc))
            cleaned.append("-I" + inc)
            continue

        # 可能是 -Dxxx
        if a == "-D":
            skip_next = True
            continue
        if a.startswith("-D"):
            cleaned.append(a)
            continue

        # 源文件参数（如 xmllint.c）可能出现在 arguments 中，且是相对路径；跳过
        if a.endswith((".c", ".cc", ".cxx", ".cpp", ".C")):
            # 不传给 clang_args，parse() 已指定文件
            continue

        # 其他 flag 原样保留（警告等无所谓）
        cleaned.append(a)

    return cleaned

def load_compile_db(json_path):
    """
    读取 compile_commands.json，返回映射:
        abs_file_path -> args_list
    """
    if not os.path.exists(json_path):
        print(f"[warn] compile_commands.json 不存在: {json_path}")
        return {}

    with open(json_path, "r") as f:
        db = json.load(f)

    file_to_args = {}

    for entry in db:
        file_path = entry.get("file")
        directory = entry.get("directory", "")
        if not file_path:
            continue

        # 绝对路径化
        if not os.path.isabs(file_path):
            file_path = os.path.normpath(os.path.join(directory, file_path))
        file_path = os.path.realpath(file_path)

        # 获取原始参数（arguments优先；否则解析command字符串）
        if "arguments" in entry and entry["arguments"]:
            raw_args = entry["arguments"]
        else:
            # fallback: split command
            cmd = entry.get("command", "")
            raw_args = cmd.split() if cmd else []

        # 清洗参数
        args = prepare_args(raw_args, directory)

        # 保存
        file_to_args[file_path] = args

    return file_to_args


def _normalize_name(name: str) -> str:
    """可按需扩展：去参数、去空格、大小写统一。"""
    return name.strip().split('(')[0]

def _build_name_index(callgraph, ignore_case=True):
    """
    返回 name->canonical 映射，方便大小写模糊匹配。
    如果 ignore_case=True，则所有键按lower比较。
    """
    idx = {}
    for fn in callgraph.keys():
        norm = _normalize_name(fn)
        key = norm.lower() if ignore_case else norm
        # 若重复，保留第一次即可（或根据需要合并）
        idx.setdefault(key, fn)
    return idx

def find_call_path(callgraph, start_func, end_func, ignore_case=True, max_depth=None):
    """
    在 callgraph 中查找从 start_func 到 end_func 的调用路径。
    返回路径列表，例如 ["A", "B", "C"] 表示 A->B->C；找不到返回 None。
    """
    # 名称归一
    idx = _build_name_index(callgraph, ignore_case=ignore_case)
    s_key = _normalize_name(start_func)
    t_key = _normalize_name(end_func)
    if ignore_case:
        s_key, t_key = s_key.lower(), t_key.lower()

    if s_key not in idx:
        print(f"[warn] 起点函数未在 callgraph 中: {start_func}")
        return None
    if t_key not in idx:
        print(f"[warn] 终点函数未在 callgraph 中: {end_func}")
        return None

    start = idx[s_key]
    target = idx[t_key]

    visited = set()
    path = []

    def dfs(cur, depth=0):
        if max_depth is not None and depth > max_depth:
            return False
        visited.add(cur)
        path.append(cur)
        if cur == target:
            return True
        for callee in callgraph.get(cur, ()):
            if callee not in visited:
                if dfs(callee, depth + 1):
                    return True
        path.pop()
        return False

    found = dfs(start)
    return path if found else None

def find_all_call_paths(callgraph, start_func, end_func, ignore_case=True, max_depth=None):
    """
    在 callgraph 中查找从 start_func 到 end_func 的所有调用路径。
    返回值是一个列表，每个元素是一条路径列表，如 ["A", "B", "C"]。
    如果没有路径，返回 []。
    """

    # 名称归一
    idx = _build_name_index(callgraph, ignore_case=ignore_case)
    s_key = _normalize_name(start_func)
    t_key = _normalize_name(end_func)
    if ignore_case:
        s_key, t_key = s_key.lower(), t_key.lower()

    if s_key not in idx:
        print(f"[warn] 起点函数未在 callgraph 中: {start_func}")
        return []
    if t_key not in idx:
        print(f"[warn] 终点函数未在 callgraph 中: {end_func}")
        return []

    start = idx[s_key]
    target = idx[t_key]

    all_paths = []
    path = []
    visited = set()

    def dfs(cur, depth=0):
        if max_depth is not None and depth > max_depth:
            return
        visited.add(cur)
        path.append(cur)

        if cur == target:
            all_paths.append(list(path))
        else:
            for callee in callgraph.get(cur, ()):
                if callee not in visited:
                    dfs(callee, depth + 1)

        path.pop()
        visited.remove(cur)

    dfs(start)
    return all_paths


def main():
    # files = entry_files if entry_files else collect_source_files(project_root)
    # index = Index.create()

    # for f in files:
    #     # print(f"Parsing {f} ...")
    #     # tu = index.parse(f, args=['-I'+project_root])
    #     tu = index.parse(f, args=clang_args,options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    #     visit(tu.cursor)


    compile_args_map = load_compile_db(compile_db_path)

    # 如果你已有 entry_files 列表，则用；否则扫描项目根
    # sources = entry_files if entry_files else collect_source_files(project_root)
    sources = compile_args_map.keys()
    index = cindex.Index.create()

    for f in sources:
        # 为该源文件查找编译参数
        args = compile_args_map.get(f)
        if args is None:
            # 尝试匹配规范化路径（某些路径大小写差异 / 符号链接）
            f_norm = os.path.normpath(f)
            if f_norm in compile_args_map:
                args = compile_args_map[f_norm]
        if args is None:
            # fallback
            args = fallback_clang_args

        # print(f"Parsing {f} ...")  # 可注释
        try:
            tu = index.parse(
                f,
                args=args,
                options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
            )
        except cindex.TranslationUnitLoadError as e:
            print(f"[err] Failed to parse {f}: {e}")
            continue

        visit(tu.cursor)




    # 输出dot格式调用图
    # print("digraph callgraph {")
    # for caller, callees in callgraph.items():
    #     for callee in callees:
    #         print(f'    "{caller}" -> "{callee}";')
    # print("}")

    call_stack = analyze_call_stack(call_stack_str)
    print(call_stack)

    # 一层调用
    # callers = set()
    # for caller, callees in callgraph.items():
    #     for callee in callees:
    #         if callee in call_stack:
    #             print(f"{caller} -> {callee}")
    #             callers.add(caller)
    #         if caller == "xmlSAX2CDataBlock":
    #             print(f"found! {caller} -> {callee}")

    # 一层检测
    # check = "xmlSAX2CDataBlock" in callers
    # callers_m = callers - set(call_stack)
    # print(f"callers:{callers}, num: {len(callers)}, xmlSAX2CDataBlock is in? {check}")
    # print(f"callers_m:{callers_m}, num: {len(callers_m)}, xmlSAX2CDataBlock is in? {check}")

    
    # callers1 = set()
    # for caller, callees in callgraph.items():
    #     for callee in callees:
    #         if callee in callers_m:
    #             print(f"{caller} -> {callee}")
    #             callers1.add(caller)
    # check = "xmlSAX2CDataBlock" in callers1
    # callers1_m = callers1 - set(callers_m)
    # print(f"callers1:{callers1}, num: {len(callers1)}, xmlSAX2CDataBlock is in? {check}")
    # print(f"callers1_m:{callers1_m}, num: {len(callers1_m)}, xmlSAX2CDataBlock is in? {check}")

    for item in call_stack:
        p = find_all_call_paths(callgraph,
                            start_func=patch_func,
                            end_func=item,
                            ignore_case=True)
        if p:
            print(f"共找到 {len(p)} 条调用路径：")
            for i, p1 in enumerate(p, 1):
                print(f"{i}: {' -> '.join(p1)}")
            # print("调用路径:", " -> ".join(p))
            # real_trace = p
        else:
            print(f"未找到调用关系:{item}")
    
    # print("真实调用链:", " -> ".join(real_trace))
    # print(f"真实调用链:{real_trace}")


if __name__ == "__main__":
    main()
