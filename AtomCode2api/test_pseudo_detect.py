# 伪回复识别的离线回归（不联网）：真伪回复必须命中、撞词正常回答必须放行。
# 运行：python test_pseudo_detect.py
import sys

from server import _detect_pseudo_reply, _retry_after_seconds

# 真实上游模板（wire-dump 与 CLI 会话文件取证的原样，含未取证时段的同族变体）
POSITIVE = [
    ("模型「glm5.3-flash」在当前 CodingPlan 用量窗口内已达上限。当前滚动窗口约在当日 03:13 结束并重置额度，请稍后重试。",
     "quota_exhausted", "03:13"),
    ("模型「qwen3.8-27b」在当前 CodingPlan 用量窗口内已达上限。当前滚动窗口约在当日 13:13 结束并重置额度，请稍后重试。",
     "quota_exhausted", "13:13"),
    ("模型「glm5.3-flash」的请求负载过高，请稍后再试。", "overloaded", None),
    ("模型「qwen3.8-27b」的请求负载过高，请稍后再试。", "overloaded", None),
    # 模板嵌在更长的正文里也必须命中（search 语义）
    ("抱歉，模型「glm5.3-flash」的请求负载过高，请稍后再试。", "overloaded", None),
    # 无重置时刻的退化为 None reset，仍须识别为 quota
    ("模型「glm5.3-flash」在当前 CodingPlan 用量窗口内已达上限，请稍后重试。",
     "quota_exhausted", None),
]

# 撞词的正常回答 / 转述场景——绝不能拦截
NEGATIVE = [
    "「请求负载过高」指服务器或系统在单位时间内收到的请求数量超出了其处理能力",
    "HTTP 429 通常配合 Retry-After 头使用，表示请求负载过高时的标准限流响应",
    "用量窗口内已达上限这个说法来自 CodingPlan 的计费文案，含义是滚动配额用尽",
    "这句话可以这样写：用量窗口内已达上限。当前滚动窗口约在当日 03:13 结束并重置额度",
    "请实现一个处理请求负载过高的限流中间件",
    "当系统提示「请求负载过高，请稍后再试」时通常意味着服务过载",
]


def main():
    fails = []
    for text, kind, reset in POSITIVE:
        got = _detect_pseudo_reply(text)
        if got != (kind, reset):
            fails.append("漏判: %r → %r 期望 %r" % (text[:44], got, (kind, reset)))
    for text in NEGATIVE:
        got = _detect_pseudo_reply(text)
        if got is not None:
            fails.append("误伤: %r → %r" % (text[:44], got))
    wait = _retry_after_seconds("03:13")
    if wait is None or not (0 < wait <= 86400):
        fails.append("retry_after 异常: %r" % wait)
    if _retry_after_seconds(None) is not None:
        fails.append("retry_after(None) 应为 None")

    if fails:
        print("\n".join(fails))
        print("FAIL (%d)" % len(fails))
        return 1
    print("PASS: %d 条真模板全部命中, %d 条撞词样本全部放行, retry_after 换算正常"
          % (len(POSITIVE), len(NEGATIVE)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
