from collections import defaultdict
from typing import Dict, List, Tuple
import subprocess
import argparse
import sqlite3
import base64
import sys
import os
import re

LINES_BEFORE = 10
LINES_AFTER = 10
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, '..', 'arvo.db')
PATCHES_PATH = os.path.join(SCRIPT_DIR, 'patches')
BUG_QUERY_BY_ID = "SELECT crash_type, crash_output, fix_commit FROM arvo WHERE project = ? AND localId = ?;"

# Extract call stack from crash output
def extract_call_stack(log: str):
    # print(log)
    # print(repr(log))
    # call_stack_pattern = re.compile(r'^\s*#\d+\s+0x[0-9a-f]+\s+in\s+.*$', re.MULTILINE)
    call_stack_pattern = re.compile(r'^.*#\d+\s+0x[0-9a-f]+\s+in\s+.*$', re.MULTILINE)
    matches = call_stack_pattern.findall(log)
    # print(repr(matches))
    return "\n".join(matches)   # Limit to first 5 lines for brevity

# Parse top stack frame to get file path and line number
def parse_top_stack_frame(stack_trace: str, repo_name: str):
    lines = stack_trace.strip().splitlines()
    if not lines:
        return None, None

    first = lines[0]
    match = re.search(r'in\s+.*?\s+(/src/(.*?):(\d+))', first)
    if match:
        file_path = match.group(2)
        if file_path.startswith(f"{repo_name}/"):
            file_path = file_path[len(repo_name) + 1:]  # Strip repo prefix and slash
        line_number = int(match.group(3))
        return file_path, line_number
    return None, None

# Get file snippet from commit
def get_file_snippet_from_commit(repo_path, commit, file_path, line_number, context=5):
    try:
        content = subprocess.check_output(
            ['git', '-C', repo_path, 'show', f'{commit}:{file_path}'],
            stderr=subprocess.DEVNULL
        ).decode().splitlines()
        start = max(0, line_number - context - 1)
        end = line_number + context
        return "\n".join(content[start:end])
    except subprocess.CalledProcessError:
        return f"⚠️ Could not retrieve {file_path} at {commit}"

# Print colored patch for a commit
def print_colored_patch(repo_path, commit_hash: str):
    # Get the patch for the commit
    patch = subprocess.check_output(['git', '-C', repo_path, 'show', '--format=', commit_hash]).decode()
    print("Files changed in commit:")
    for line in patch.splitlines():
        if line.startswith("diff --git"):
            print(f"\033[96m{line}\033[0m")  # bold cyan
        elif line.startswith("@@"):
            print(f"\033[95m{line}\033[0m")  # bold magenta
        elif line.startswith("+") and not line.startswith("+++"):
            print(f"\033[92m{line}\033[0m")  # green
        elif line.startswith("-") and not line.startswith("---"):
            print(f"\033[91m{line}\033[0m")  # red
        else:
            print(f"\033[90m{line}\033[0m")  # dim white

def print_colored_diff(repo_path, commit1: str, commit2: str):
    diff = subprocess.check_output(['git', '-C', repo_path, 'diff', commit1, commit2]).decode()
    print(f"Diff between {commit1} and {commit2}:")
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            print(f"\033[96m{line}\033[0m")  # cyan
        elif line.startswith("@@"):
            print(f"\033[95m{line}\033[0m")  # magenta
        elif line.startswith("+") and not line.startswith("+++"):
            print(f"\033[92m{line}\033[0m")  # green
        elif line.startswith("-") and not line.startswith("---"):
            print(f"\033[91m{line}\033[0m")  # red
        else:
            print(f"\033[90m{line}\033[0m")  # dim white

# Analyze crashes reading from the database
def analyze_crashes(index, repo_path, crash_commit, target_rows=None):
    for idx, (crash_type, crash_output, fix_commit) in enumerate(target_rows):
        print(f"[#{idx}] Crash Type: {crash_type}\n")
        
        print("=== Call Stack ===")
        call_stack = extract_call_stack(crash_output)
        print(call_stack)
        
        print("\nFix Commit:", fix_commit)
        if not fix_commit:
            print("❌ No fix_commit available\n" + "-" * 80)
            continue

        # Get parent commit (i.e., buggy version)
        try:
            parent_commit = subprocess.check_output(['git', '-C', repo_path, 'rev-parse', f'{fix_commit}^']).decode().strip()
        except subprocess.CalledProcessError:
            print("⚠️ Could not find parent commit.\n" + "-" * 80)
            continue
        print("Parent Commit:", parent_commit)
        print("Crash Commit:", crash_commit)

        # Extract file and line number from call stack
        file, line = parse_top_stack_frame(extract_call_stack(crash_output), os.path.basename(repo_path.rstrip('/')))
        if file:
            snippet_lines = get_file_snippet_from_commit(repo_path, parent_commit, file, line).splitlines()
            start_line = line - len(snippet_lines) // 2

            print(f"📍 Code near {file}:{line} at {parent_commit[:8]}:")
            for i, code_line in enumerate(snippet_lines):
                current_line = start_line + i
                if current_line == line:
                    print(f"\033[93m👉{code_line}\033[0m")  # yellow
                else:
                    print(f"\033[90m  {code_line}\033[0m")  # dim white

        # Print colored patch for the fix commit
        print_colored_patch(repo_path, fix_commit)
        print_colored_diff(repo_path, crash_commit, fix_commit)
        single_patch = os.path.join(PATCHES_PATH, f"{index}-single.patch")
        real_patch = os.path.join(PATCHES_PATH, f"{index}-real.patch")
        run_shell(f"git diff parent_commit fix_commit > {single_patch}", repo_path)
        run_shell(f"git diff crash_commit fix_commit > {real_patch}", repo_path)
        
        print("-" * 80)
    return parent_commit, fix_commit, call_stack


# A helper function to run shell commands and handle errors
def run_shell(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, shell=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0 and not result.stdout:
        print(f"[!] Command failed: {command}")
        print(result.stdout)
        sys.exit(1)
    return result.stdout.strip()

# Run arvo inside the container to capture the crash log
# def run_arvo_and_get_crash_log():
#     print(f"[*] Running arvo inside {CONTAINER_IMAGE} container to get crash log...")
#     cmd = f'docker run --rm -i {CONTAINER_IMAGE} arvo'
#     output = run_shell(cmd)
#     print("[+] Crash log captured.")
#     return output

def run_arvo_and_get_crash_log(container_id): 
    print(f"[*] Running arvo inside {CONTAINER_IMAGE} container to get crash log...")
    print(f"[*] Starting container {container_id}...")
    run_shell(f"docker start {container_id}")
    try:
        print(f"[*] Running arvo inside from container {container_id}...")
        cmd = f'docker exec {container_id} arvo'
        output = run_shell(cmd)
        print("[+] Crash log captured.")
        return output
    finally:
        print(f"[*] Stopping container {container_id}...")
        run_shell(f"docker stop {container_id}")

# Parse the crash log to extract the function name, file path, and line number
def parse_crash_log(log) -> tuple:
    print("[*] Parsing crash log to extract file and line number...")
    match = re.search(r'#0\s+0x[0-9a-f]+\s+in\s+(\w+)\s+([^\s:]+):(\d+)', log)
    if match:
        function = match.group(1)
        filepath = match.group(2)
        line_number = int(match.group(3))
        bug_match = re.search(r'==\d+==\w+: \w+: ([^:\n]+)', log)
        bug_type = bug_match.group(1) if bug_match else "Unknown"
        print(f"[+] Found crash in function: {function}, file: {filepath}, line: {line_number}")
        print(f"[+] Bug type: {bug_type}")
        return function, filepath, line_number, bug_type
    else:
        print("[!] Could not parse crash log.")
        sys.exit(1)

# Extract the commit hash of the vulnerable commit from the container
# def get_vulnerable_commit_hash():
#     print("[*] Extracting commit hash from container...")
#     cmd = f'docker run --rm -i {CONTAINER_IMAGE} bash -c "git --git-dir={DOCKER_PATH}/.git --work-tree={DOCKER_PATH} log -n1 --format=%H"'
#     output = run_shell(cmd)
#     print(f"[+] Vulnerable commit: {output}")
#     return output

def get_vulnerable_commit_hash(container_id): 
    # print(f"[*] Starting container {container_id}...")
    run_shell(f"docker start {container_id}")
    try:
        print(f"[*] Extracting commit hash from container {container_id}...")
        cmd = f'docker exec {container_id} bash -c "git --git-dir={DOCKER_PATH}/.git --work-tree={DOCKER_PATH} log -n1 --format=%H"'
        output = run_shell(cmd)
        print(f"[+] Vulnerable commit: {output}")
        return output
    finally:
        print(f"[*] Stopping container {container_id}...")
        run_shell(f"docker stop {container_id}")

# Checkout the specified commit in the local repository
def checkout_commit(repo_path, commit_hash):
    print(f"[*] Checking out commit {commit_hash}...")
    run_shell(f"git checkout {commit_hash}", cwd=repo_path)

# Find the file containing the crash function in the local repository
def find_crash_function_file(repo_path, function_name):
    print(f"[*] Searching for function '{function_name}'...")
    grep_cmd = f'grep -rl "{function_name}" .'
    output = run_shell(grep_cmd, cwd=repo_path)
    files = output.splitlines()
    if not files:
        print("[!] Function not found in repo.")
        sys.exit(1)
    print(f"[+] Found in: {files[0]}")
    return os.path.join(repo_path, files[0])

# Extract the context around the crash function in the specified file
def extract_code_context(file_path, function_name, before=10, after=10):
    print(f"[*] Extracting context from {file_path}...")
    with open(file_path, 'r') as f:
        lines = f.readlines()

    match_line = None
    for i, line in enumerate(lines):
        if function_name in line:
            match_line = i
            break

    if match_line is None:
        print("[!] Function not found in file.")
        sys.exit(1)

    start = max(0, match_line - before)
    end = min(len(lines), match_line + after + 1)
    context = ''.join(lines[start:end])
    return start + 1, end, context  # lines are 1-indexed

# Write the prompt to a file for LLM input
def write_prompt(sancov_content, sancov_result, crash_log, commit_hash, crash_function, file_path, start_line, crash_line, end_line, context, output_path):
    print(f"[*] Writing prompt to {output_path}...")
    prompt = f'''You are an expert in C and the {PROJECT_NAME} codebase.
### Crash Report
Call Stack: 
{extract_call_stack(crash_log)}

### POC Coverage
sancov content:
{sancov_content}

### Concerned Code
{sancov_result}

### Buggy Commit
Commit Hash: {commit_hash}

### Crash Function
{crash_function}

### Code Context
File: {file_path}
Crash Line: {crash_line}
display Lines: {start_line} to {end_line}

```c
{context}
```
'''
    with open(output_path, 'w') as f:
        f.write(prompt)

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Generate bug prompt from ARVO crash")
    parser.add_argument("-id", "--id", required=True, help="Local Bug ID in ARVO (e.g., 42528804)")
    parser.add_argument("-r", "--repo", required=True, help="Path to the host repository")
    parser.add_argument("-d", "--docker-path", required=True, help="Path inside Docker to the source directory (e.g., /src/libxml2)")
    return parser.parse_args()

# Initialize global variables for container image and Docker path
def initialize_paths(args):
    global CONTAINER_IMAGE
    global DOCKER_PATH
    global PROJECT_NAME
    CONTAINER_IMAGE = f"n132/arvo:{args.id}-vul"
    DOCKER_PATH = args.docker_path
    LOCAL_REPO_PATH = os.path.abspath(args.repo)
    PROJECT_NAME = os.path.basename(LOCAL_REPO_PATH)
    return LOCAL_REPO_PATH

# Extract context around the crash line in the specified file
def extract_context(crash_file, crash_line, docker_path, repo_path):
    file_path = os.path.join(repo_path, os.path.relpath(crash_file, docker_path))
    start_line = max(1, crash_line - LINES_BEFORE)
    end_line = crash_line + LINES_AFTER
    with open(file_path, 'r') as f:
        lines = f.readlines()
    context = ''.join(lines[start_line - 1:end_line])
    return file_path, start_line, end_line, context


def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    success = (result.returncode == 0)

    # if stdout:
    #     print(stdout)
    # if stderr:
    #     print(stderr, file=sys.stderr)

    return {
        'success': success,
        'stdout': stdout,
        'stderr': stderr,
        'returncode': result.returncode
    }


def get_image_id(image_name):
    result = subprocess.run(
        f"docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}} {{{{.ID}}}}' | grep '^{image_name} '",
        shell=True, capture_output=True, text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        print(f"Image '{image_name}' not found.")
        return None
    return result.stdout.strip().split()[-1]
def get_container_id(image_name):
    print(f"build image: {image_name}")
    res = run_cmd(f"docker run -dit {image_name} bash")
    if res['success']:
        container_id = res['stdout']
        print(f"Container ID: {container_id}")
        print(f"[*] Stopping container {container_id}...")
        run_shell(f"docker stop {container_id}")
        return container_id
    else:
        print(f"Failed to start container: {res['stderr']}")
        # print(f"[*] Stopping container {container_id}...")
        # run_shell(f"docker stop {container_id}")
        return None

def docker_change_build(container_id, sanitizer_type):
    flags_to_add = f'''export CFLAGS="$CFLAGS -O1 -g -fsanitize={sanitizer_type} -fsanitize-coverage=trace-pc-guard,trace-cmp"
export CXXFLAGS="$CXXFLAGS -O1 -g -fsanitize={sanitizer_type} -fsanitize-coverage=trace-pc-guard,trace-cmp"
'''
    print(f"[*] Starting container {container_id} for modification...")
    run_shell(f"docker start {container_id}")
    
    try:
        print(f"[*] Adding sanitizer flags to /src/build.sh in container {container_id}")
        
        create_temp_cmd = f'echo "{flags_to_add}" > /tmp/new_build.sh'
        run_shell(f"docker exec {container_id} bash -c '{create_temp_cmd}'")
        
        append_cmd = f'cat /src/build.sh >> /tmp/new_build.sh'
        run_shell(f"docker exec {container_id} bash -c '{append_cmd}'")
        
        replace_cmd = f'mv /tmp/new_build.sh /src/build.sh'
        run_shell(f"docker exec {container_id} bash -c '{replace_cmd}'")
        
        verify_cmd = f'head -n2 /src/build.sh'
        output = run_shell(f"docker exec {container_id} bash -c '{verify_cmd}'")
        
        if f"fsanitize={sanitizer_type}" in output:
            print(f"[+] Sanitizer flags added successfully to container {container_id}")
        else:
            print(f"[-] Failed to add sanitizer flags to container {container_id}")
            print(f"    Verification output: {output}")
    finally:
        print(f"[*] Stopping container {container_id} after changing build...")
        run_shell(f"docker stop {container_id}")

def docker_change_arvo(container_id):
    print(f"[*] Starting container {container_id} for sanitizer configuration...")
    run_shell(f"docker start {container_id}")
    
    try:
        print(f"[*] Checking SANITIZER type in /bin/arvo in container {container_id}")
        
        check_cmd = f'grep "export SANITIZER=" /bin/arvo || echo "NOT_FOUND"'
        sanitizer_output = run_shell(f"docker exec {container_id} bash -c '{check_cmd}'")
        
        if "memory" in sanitizer_output:
            sanitizer_type = "memory"
            options = "MSAN_OPTIONS"
            print(f"[+] Found memory sanitizer, adding MSAN configuration")
        elif "address" in sanitizer_output:
            sanitizer_type = "address"
            options = "ASAN_OPTIONS"
            print(f"[+] Found address sanitizer, adding ASAN configuration")
        else:
            print(f"[-] Error: No valid SANITIZER type found in /bin/arvo")
            print(f"    Output: {sanitizer_output}")
            return
        
        temp_file = "/tmp/arvo_modified"
#         add_config_cmd = f'''cp /bin/arvo {temp_file}
# last_export_line=$(grep -n "export " {temp_file} | tail -1 | cut -d: -f1)
# sed -i "$((last_export_line+1))i export {options}=coverage=1:coverage_dir=/tmp/coverage" {temp_file}
# sed -i "$((last_export_line+2))i mkdir -p /tmp/coverage" {temp_file}
# sed -i "$((last_export_line+3))i chmod 777 /tmp/coverage" {temp_file}
# mv {temp_file} /bin/arvo
#         '''
        run_shell(f"docker start {container_id}")
        cmd1=f'cp /bin/arvo {temp_file}'
        run_shell(f"docker exec {container_id} bash -c '{cmd1}'")
        cmd2=f'grep -n "export " {temp_file} | tail -1 | cut -d: -f1'
        last_export_line = run_shell(f"docker exec {container_id} bash -c '{cmd2}'")
        last_export_line1 = eval(last_export_line)+1
        last_export_line2 = eval(last_export_line)+2
        last_export_line3 = eval(last_export_line)+3
        cmd3=f'sed -i "{last_export_line1}i export {options}=coverage=1:coverage_dir=/tmp/coverage" {temp_file}'
        run_shell(f"docker exec {container_id} bash -c '{cmd3}'")
        cmd4=f'sed -i "{last_export_line2}i mkdir -p /tmp/coverage" {temp_file}'
        run_shell(f"docker exec {container_id} bash -c '{cmd4}'")
        cmd5=f'sed -i "{last_export_line3}i chmod 777 /tmp/coverage" {temp_file}'
        run_shell(f"docker exec {container_id} bash -c '{cmd5}'")
        # cmd6=f'sed -i -E "s|^([[:space:]]*/out/[^[:space:]]+)[[:space:]]+(/tmp/poc[[:space:]]*)$|\1 -timeout=10 -dump_coverage=1 \2|g" {temp_file}'
        cmd6=fr'sed -i -E "s|^([[:space:]]*/out/[^[:space:]]+)[[:space:]]+(/tmp/poc[[:space:]]*)$|\1 -timeout=10 -dump_coverage=1 \2|g" {temp_file}'
        run_shell(f"docker exec {container_id} bash -c '{cmd6}'")
        cmd7=f'mv {temp_file} /bin/arvo'
        run_shell(f"docker exec {container_id} bash -c '{cmd7}'")
        



        verify_cmd = f'grep "{options}=coverage=1:coverage_dir=/tmp/coverage" /bin/arvo'
        output = run_shell(f"docker exec {container_id} bash -c '{verify_cmd}'")
        
        mkdir_cmd = f'grep "mkdir -p /tmp/coverage" /bin/arvo'
        mkdir_output = run_shell(f"docker exec {container_id} bash -c '{mkdir_cmd}'")
        
        chmod_cmd = f'grep "chmod 777 /tmp/coverage" /bin/arvo'
        chmod_output = run_shell(f"docker exec {container_id} bash -c '{chmod_cmd}'")
        
        if options in output and "mkdir" in mkdir_output and "chmod" in chmod_output:
            print(f"[+] Sanitizer configuration added successfully to container {container_id}")
            print(f"    Added configuration:")
            print(f"    {output.strip()}")
            print(f"    {mkdir_output.strip()}")
            print(f"    {chmod_output.strip()}")
        else:
            print(f"[-] Failed to add sanitizer configuration to container {container_id}")
            print(f"    Verification results:")
            print(f"    Options line: {'Found' if options in output else 'Missing'}")
            print(f"    mkdir command: {'Found' if mkdir_output else 'Missing'}")
            print(f"    chmod command: {'Found' if chmod_output else 'Missing'}")
    finally:
        print(f"[*] Stopping container {container_id} after changing arvo...")
        run_shell(f"docker stop {container_id}")
        return sanitizer_type

def docker_recompile(container_id, docker_path):
    print(f"[*] Recompiling Arvo in container {container_id}...")
    run_shell(f"docker start {container_id}")
    
    try:
        target_path = os.path.join(docker_path, "jxsan.sh")
        newfile='''#!/bin/bash

BIN="$1"
SANCOV="$2"

if [ ! -f "$BIN" ] || [ ! -f "$SANCOV" ]; then
    echo "Usage: $0 <path_to_binary> <path_to_sancov>"
    exit 1
fi


od -An -t x8 "$SANCOV" | tr -s ' ' | while read addr; do
    addr2line -e "$BIN" "$addr"
done
'''
        # cmd_newfile = f'cat > "{target_path}" << {newfile}'
        # cmd_newfile_chmod = f'chmod +x "{target_path}"'
        # run_shell(f"docker exec {container_id} bash -c '{cmd_newfile}'")
        # run_shell(f"docker exec {container_id} bash -c '{cmd_newfile_chmod}'")
        # print("[*] Build jxsan.sh Done!")

#         create_cmd = f'''bash -c 'cat > "{target_path}" << \\"EOF\\"
# {newfile}
# EOF'
# '''
        encoded_content = base64.b64encode(newfile.encode()).decode()
    
        create_cmd = f'''bash -c 'base64 -d <<< "{encoded_content}" > "{target_path}"' '''

        print(f"[*] Creating {target_path} in container {container_id}")
        run_shell(f"docker exec {container_id} {create_cmd}")
        
        print(f"[*] Setting execute permission on {target_path}")
        run_shell(f"docker exec {container_id} chmod +x '{target_path}'")
        
        verify_cmd = f'''bash -c '[ -f "{target_path}" ] && head -n5 "{target_path}" || echo "File not created"'
        '''
        output = run_shell(f"docker exec {container_id} {verify_cmd}")
        print(f"[*] Verification output:\n{output}\nStarting recompile...")


        run_shell(f"docker exec {container_id} bash -c 'arvo compile'")
        print("[*] arvo compile Done!")

    finally:
        print(f"[*] Stopping container {container_id} after recompilation...")
        run_shell(f"docker stop {container_id}")

def docker_gen_coverage(container_id, crash_log):
    sancov_result = "no content"
    try:
        pattern = r"SanitizerCoverage:\s+([^\s]+\.sancov)"
        match = re.search(pattern, crash_log)
        sancov_file = match.group(1) if match else None
        bin_file = sancov_file.split("/")[-1].split(".")[0]
        print(f"[*] sancov_file: {sancov_file}")
        print(f"[*] bin_file: {bin_file}")
        run_shell(f"docker start {container_id}")
        cmd = f'./jxsan.sh  /out/{bin_file} {sancov_file}'
        sancov_result = run_shell(f"docker exec {container_id} bash -c '{cmd}'")

    finally:
        print(f"[*] Stopping container {container_id} after recompilation...")
        run_shell(f"docker stop {container_id}")
        return sancov_result

def read_surrounding_lines(filepath, upper_line, lower_line):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    total_lines = len(lines)

    # 行号从1开始，Python索引从0开始
    start = max(upper_line - 1, 0)
    end = min(lower_line, total_lines)

    # 返回对应的行和它们的实际行号
    return [(i + 1, lines[i].rstrip('\n')) for i in range(start, end)]

def merge_intervals(intervals: List[Tuple[int, int]]) -> List[List[int]]:
    if not intervals:
        return []

    # 先按起始位置排序
    intervals.sort()
    merged = [list(intervals[0])]

    for current in intervals[1:]:
        prev = merged[-1]
        if current[0] <= prev[1]:  # 有重叠
            prev[1] = max(prev[1], current[1])
        else:
            merged.append(list(current))
    return merged


def compute_merged_ranges(file_to_lines: Dict[str, List[int]], threshold: int) -> Dict[str, List[List[int]]]:
    file_to_ranges = {}

    for filename, lines in file_to_lines.items():
        intervals = []
        for line in lines:
            start = max(1, line - threshold)  # 防止负行号
            end = line + threshold
            intervals.append((start, end))

        merged = merge_intervals(intervals)
        file_to_ranges[filename] = merged

    return file_to_ranges

def analysis_sancov(sancov_content, yz, docker_path, repo_path):
    sancov_dict = defaultdict(list)
    min_dict = {}
    max_dict = {}
    sancov_list = []
    lines = [os.path.relpath(line.strip(),docker_path) for line in sancov_content.split("\n") if line.startswith(docker_path+"/")]
    for line in lines:
        tmplist = line.split(":")
        sancov_dict[tmplist[0]].append(int(tmplist[1]))
        if tmplist[0] not in sancov_list:
            sancov_list.append(tmplist[0])
        if tmplist[0] not in min_dict:
            min_dict[tmplist[0]] = int(tmplist[1])
        elif min_dict[tmplist[0]] > int(tmplist[1]):
            min_dict[tmplist[0]] = int(tmplist[1])
        if tmplist[0] not in max_dict:
            max_dict[tmplist[0]] = int(tmplist[1])
        elif max_dict[tmplist[0]] < int(tmplist[1]):
            max_dict[tmplist[0]] = int(tmplist[1])
    qj_dict = compute_merged_ranges(dict(sancov_dict), threshold=yz)
    result=[]
    # print(result)
    for file in sancov_list:
        result.append(f"##{file}:\n...")
        for qj in qj_dict[file]:
            context = read_surrounding_lines(os.path.join(repo_path, file), qj[0], qj[1])
            for lineno, line in context:
                result.append(f"{lineno}: {line}")
            result.append("...")
        result.append("\n")
    # return dict(sancov_dict)
    return "\n".join(result)


def exec_docker(container_id, src_path, docker_path):
    run_cmd(f"docker cp {src_path} {container_id}:{docker_path}")
    print(f"Copied {src_path} to {container_id}:{docker_path}, starting to compile...")
    res1 = run_cmd(f'docker exec -it {container_id} bash -c "arvo compile"')
    if not res1['success']:
        print(f"Failed to compile: stderr: {res1['stderr']}")
        return 0,res1
    print(f"Compile finished, starting to poc...")
    res2 = run_cmd(f'docker exec -it {container_id} bash -c "arvo"')
    if not res2['success']:
        print(f"Failed to poc: {res2['stderr']}")
        return 1,res2
    print(f"poc finished!!!")
    return 2,res2
    

def clean_docker(container_id, image_name):
    run_cmd(f"docker rm -f {container_id}")
    print(f"Deleting container: {container_id}")
    # run_cmd(f"docker rmi {image_name}")
    # print(f"Deleting image: {image_name}")
    run_cmd("docker system prune -f")
    print("Pruning dangling resources...")

def main():
    parser = argparse.ArgumentParser(description="all in one")
    parser.add_argument("-id", "--id", required=True, help="Local Bug ID in ARVO (e.g., 42470114)")
    parser.add_argument("-r", "--repo", required=True, help="Path to the host repository")
    parser.add_argument("--docker-path", "-d", type=str, required=True, help="Path inside Docker to the source directory (e.g., /src/libxml2)")
    args = parser.parse_args()

    # checkout local repo to vulnerable commit
    print("!!------------ PROCESS0: Checkout local repo ------------!!")
    LOCAL_REPO_PATH = initialize_paths(args)
    container_id = get_container_id(CONTAINER_IMAGE)
    commit_hash = get_vulnerable_commit_hash(container_id)
    checkout_commit(LOCAL_REPO_PATH, commit_hash)

    # trace_pc
    print("!!------------ PROCESS1: Get coverage ------------!!")
    sanitizer_type = docker_change_arvo(container_id)
    docker_change_build(container_id, sanitizer_type)
    docker_recompile(container_id, DOCKER_PATH)

    # gen_prompt
    print("!!------------ PROCESS2: Generating prompt ------------!!")
    crash_log = run_arvo_and_get_crash_log(container_id)
    sancov_content = docker_gen_coverage(container_id, crash_log)
    print("[*] sancov_content: ", sancov_content, "\n")
    sancov_result = analysis_sancov(sancov_content, 50, args.docker_path, LOCAL_REPO_PATH)

    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if args.id is not None:
        cursor.execute(BUG_QUERY_BY_ID, (PROJECT_NAME, args.id))
        target_rows = cursor.fetchall()
        if not target_rows:
            print(f"No bug found with localId {args.id}")
            return

    # Analyze the specified crash or all crashes
    parent_commit, fix_commit, call_stack = analyze_crashes(args.id, args.repo, commit_hash, target_rows)

    CRASH_LOG_FILE = os.path.join(SCRIPT_DIR, f"crash_log_before_{args.id}.txt")
    with open(CRASH_LOG_FILE, "w") as f:
        f.write(crash_log)
    crash_function, crash_file, crash_line, bug_type = parse_crash_log(crash_log)
    print(f"Crash detected in function: {crash_function} at {crash_file}:{crash_line} (type: {bug_type})")

    file_path, start_line, end_line, context = extract_context(crash_file, crash_line, args.docker_path, LOCAL_REPO_PATH)
    OUTPUT_PROMPT_FILE = os.path.join(SCRIPT_DIR, f"llm_bug_prompt_{args.id}.txt")
    write_prompt(sancov_content, sancov_result, crash_log, commit_hash, crash_function, file_path, start_line, crash_line, end_line, context, OUTPUT_PROMPT_FILE)

    # gen_patch
    patch_times = 0

    # docker ps
    # docker ps -aq
    # docker run -it n132/arvo:42470114-vul bash
    # docker cp ./build.sh 938a94340120:/src/build.sh
    # docker start 938a94340120
    # docker exec -it 938a94340120 bash
    # cat /src/build.sh
    # readelf -n /out/libxml2_xml_read_memory_fuzzer | grep -i sanitizer
    # nm /out/libxml2_xml_read_memory_fuzzer | grep __sanitizer_cov
    # cat $(which arvo)
    # arvo compile
    # arvo
    # docker rm -f $(docker ps -aq)
    # dos2unix build.sh
    # dos2unix arvo
    # docker cp ./arvo 50176b39acb5:/bin/arvo
    # cat /bin/arvo
    # chmod +x /bin/arvo
    # strings /out/libxml2_xml_read_memory_fuzzer | grep -i profile
    # file /tmp/profile.profraw
    # llvm-profdata merge -sparse /tmp/profile.profraw -o /tmp/output.profdata
    # llvm-cov show /out/libxml2_xml_read_memory_fuzzer -instr-profile=/tmp/output.profdata -format=html -output-dir=/tmp/coverage_html
    # docker cp 50176b39acb5:/tmp/coverage_html ./coverage_html
    # chmod +x jxsan.sh
    # ./jxsan.sh  /out/libxml2_xml_read_memory_fuzzer /tmp/coverage/libxml2_xml_read_memory_fuzzer.77882.sancov





    # after_patch
    # print("!!------------ PROCESS3: patching&poc ------------!!")
    # image_name = f"n132/arvo:{args.id}-vul"
    # docker_path = args.docker_path
    # image_id = get_image_id(image_name)

    # if not image_id:
    #     return
    # container_id = get_container_id(image_name)
    # src_path = "/mnt/sdb/oss-fuzz/arvo/ARVO-Meta/scripts"
    # stas, result = exec_docker(container_id, src_path, docker_path)
    # with open(f"crash_log_after_{args.id}_{stas}.txt", "w") as f:
    #     f.write(result['stdout'])
    # clean_docker(container_id, CONTAINER_IMAGE)

    # docker system prune -a --volumes -f
    # docker rm -f $(docker ps -aq)

if __name__ == "__main__":
    main()
    # python arvo-allinone.py -id 42470114 -d /src/libxml2
    # python arvo-allinone.py -r ./libxml2 -id 42470114 -d /src/libxml2
    # 问题，有时候会段错误，不一定出现