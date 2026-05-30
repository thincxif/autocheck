import angr
import claripy
import json
import re
import subprocess
from openai import OpenAI

BINARY = "./crackme"

client = OpenAI(
    api_key="YOUR_API_KEY_HERE",
    base_url="https://api.deepseek.com"
)

_found_state = None
_found_input_var = None

def tool_explore_and_save(find_symbol, avoid_symbol):
    global _found_state, _found_input_var
    proj = angr.Project(BINARY, auto_load_libs=False)
    flag_chars = claripy.BVS("flag", 8 * 9)
    state = proj.factory.full_init_state(
        stdin=angr.SimFile("/dev/stdin", content=flag_chars)
    )
    sm = proj.factory.simulation_manager(state)
    sm.explore(
        find=lambda s: find_symbol.encode() in s.posix.dumps(1),
        avoid=lambda s: avoid_symbol.encode() in s.posix.dumps(1),
        num_find=1
    )
    result = {
        "found": len(sm.found),
        "active": len(sm.active),
        "deadended": len(sm.deadended),
    }
    if sm.found:
        _found_state = sm.found[0]
        _found_input_var = flag_chars
        result["message"] = "成功找到目标路径！请调用solve_input求解输入。"
        result["stdout"] = sm.found[0].posix.dumps(1).decode(errors='replace')
    else:
        result["message"] = "未找到目标路径。"
    return result

def tool_solve_input():
    global _found_state, _found_input_var
    if _found_state is None:
        return {"error": "还没有找到目标状态，请先调用explore工具。"}
    solver = _found_state.solver
    concrete = solver.eval(_found_input_var, cast_to=bytes)
    raw = concrete.split(b'\x00')[0]
    password = ''.join(c for c in raw.decode(errors='replace') if c.isprintable())
    return {
        "password": password,
        "raw_bytes": list(concrete[:9]),
        "message": f"求解成功！密码为: {password}"
    }

TOOLS = {
    "explore": tool_explore_and_save,
    "solve_input": tool_solve_input
}

def call_llm(messages):
    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=messages,
        temperature=0.0
    )
    return resp.choices[0].message.content

def parse_action(text):
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            if "action" in data and "tool" not in data:
                data["tool"] = data.pop("action")
            if "parameters" in data and "args" not in data:
                data["args"] = data.pop("parameters")
            return data
        except:
            pass
    return None

def main():
    print("=" * 60)
    print("ReAct Agent 启动")
    print("=" * 60)

    steps = [
        {"role": "user", "content": "第1轮：请调用explore工具，find_symbol='Success', avoid_symbol='trapped'，探索程序路径。"},
        {"role": "user", "content": "第2轮：根据上一轮观察结果，请再次调用explore工具，find_symbol='Flag', avoid_symbol='dead loop'，进一步确认路径。"},
        {"role": "user", "content": "第3轮：已确认找到目标路径，请调用solve_input工具求解最终密码。"},
    ]

    system_prompt = """你是一个逆向分析Agent，严格按照用户指示调用工具。
输出必须是合法JSON格式：{"thought": "分析思路", "tool": "工具名", "args": {参数}}
可用工具：
1. explore(find_symbol, avoid_symbol)
2. solve_input()"""

    messages = [{"role": "system", "content": system_prompt}]

    final_password = None

    for i, step in enumerate(steps):
        round_num = i + 1
        print(f"\n{'='*20} 第 {round_num} 轮 {'='*20}")
        messages.append(step)

        print("[Thought] LLM思考中...")
        llm_output = call_llm(messages)
        print(f"[LLM输出]\n{llm_output}")

        action = parse_action(llm_output)
        if not action:
            print("[错误] 无法解析LLM输出")
            continue

        tool_name = action.get("tool", "")
        args = action.get("args", {})

        print(f"\n[Action] 调用工具: {tool_name}")
        print(f"[Args] {args}")

        if tool_name not in TOOLS:
            observation = {"error": f"未知工具: {tool_name}"}
        else:
            try:
                if args:
                    observation = TOOLS[tool_name](**args)
                else:
                    observation = TOOLS[tool_name]()
            except Exception as e:
                observation = {"error": str(e)}

        print(f"[Observation] {json.dumps(observation, ensure_ascii=False, indent=2)}")
        messages.append({"role": "assistant", "content": llm_output})
        messages.append({"role": "user", "content": f"Observation：{json.dumps(observation, ensure_ascii=False)}"})

        if tool_name == "solve_input" and "password" in observation:
            final_password = observation["password"]
            print(f"\n{'='*60}")
            print(f"[完成] 找到密码: {final_password}")
            print(f"{'='*60}")

    # 自动验证
    if final_password:
        print(f"\n[验证] 正在用密码 '{final_password}' 运行crackme...")
        try:
            result = subprocess.run(
                ["./crackme"],
                input=final_password + "\n",
                capture_output=True,
                text=True,
                timeout=5
            )
            print(f"[验证] 程序输出: {result.stdout.strip()}")
            if "Success" in result.stdout:
                print("[验证] ✓ 密码正确！")
            else:
                print("[验证] ✗ 密码错误！")
        except subprocess.TimeoutExpired:
            print("[验证] 超时，可能进入死循环")

    print("\n[日志结束]")

if __name__ == "__main__":
    main()
