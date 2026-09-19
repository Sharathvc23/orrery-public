"""AG-UI event constructors (community_member.agui).

Locks the wire contract AG-UI clients pattern-match on: the ``type`` strings and
camelCase field names MUST stay stable. Classification: HAPPY / EDGE.
"""

import json

from community_member import agui


def test_run_lifecycle_events():  # HAPPY
    rid = agui.new_id()
    assert agui.run_started(run_id=rid, thread_id="t")["type"] == "RunStarted"
    assert agui.run_started(run_id=rid, thread_id="t")["threadId"] == "t"
    assert agui.run_finished(run_id=rid)["type"] == "RunFinished"


def test_run_error_truncates_message():  # EDGE
    e = agui.run_error(run_id="r", message="x" * 600)
    assert e["type"] == "RunError"
    assert len(e["message"]) == 500


def test_text_message_events():  # HAPPY
    mid = agui.new_id()
    assert agui.text_message_start(message_id=mid)["role"] == "assistant"
    c = agui.text_message_content(message_id=mid, delta="hi")
    assert c["type"] == "TextMessageContent" and c["delta"] == "hi" and c["messageId"] == mid
    assert agui.text_message_end(message_id=mid)["type"] == "TextMessageEnd"


def test_tool_call_events():  # HAPPY
    tid = agui.new_id()
    s = agui.tool_call_start(tool_call_id=tid, tool_call_name="search_chapter")
    assert s["type"] == "ToolCallStart" and s["toolCallName"] == "search_chapter" and s["toolCallId"] == tid
    a = agui.tool_call_args(tool_call_id=tid, delta='{"q":1}')
    assert a["type"] == "ToolCallArgs" and a["delta"] == '{"q":1}'
    assert agui.tool_call_end(tool_call_id=tid)["type"] == "ToolCallEnd"
    r = agui.tool_call_result(tool_call_id=tid, content="ok")
    assert r["type"] == "ToolCallResult" and r["content"] == "ok" and r["role"] == "tool"


def test_encode_sse_frame_is_one_data_line():  # HAPPY
    frame = agui.encode_sse({"type": "RunStarted"})
    assert frame.startswith(b"data: ") and frame.endswith(b"\n\n")
    assert json.loads(frame[len(b"data: ") : -2].decode())["type"] == "RunStarted"


def test_new_id_is_unique():  # EDGE
    assert agui.new_id() != agui.new_id()
