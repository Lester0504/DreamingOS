#!/usr/bin/env python3
"""「热门目的地」卡片的字节来源与维度契约。

用户报告：「就这几个目的地加一起不到 1M，别告诉我这个路由器这么多天上网数据不到 1M」。

根因：`overviewMarkup()` 里的三元表达式是
`destinationItems.length ? destinationItems : <摘要字段>`，而 `destinationItems`
来自 `geoDestinationItems()`，包装的是地图点位。只要地图有任何一个点，摘要字段
就永远拿不到机会。

而地图点位的 bytes 是后端按 `history_sample_limit:100` 采样累加的结果，响应里
`capabilities.byte_accounting_exact:false` 与 `exact_window_bytes:false` 已经如实
声明了这一点。实测同一时刻两个数据源差一个数量级：

    geo points[].bytes 合计               2,024,295
    top_all_count_by_destination 合计    15,591,142   （2026-08-03 复测 42,095,511）

还有第二个问题：维度被偷换了。geo 点位是国家/地区（CN、US、SG），摘要是目的主机
（ports.debian13.com、114.114.114.114）。卡片标题写着「热门目的地」，却在有地图数据时
展示目的**国**。

2026-08-04 用户改了需求：「目的地应该是地方，例如美国洛杉矶。这里可以加对应国家的旗帜」。
所以维度**回到地理**，但本契约的核心保护不变，而且更要紧：
geo 的字节仍然是采样值（同日实测 regions 176 条流 / 48.8MB vs 摘要主机榜
3085 条流 / 21.5MB，两个口径互不可比），**绝不允许把它当成全窗口用量显示**。

因此现在守的是：

1. 地点榜只报流数，不报 geo 字节 —— 这才是当初那个「不到 1M」缺陷的实质。
2. `geoDestinationItems()` 仍必须不存在：它的问题是把采样字节包装成列表字节。
3. geo 点位仍然要服务地图渲染。
4. geo 不可用时必须回退到主机维度，卡片不能变空白。
5. 采样徽标/精确性标记必须继续被尊重。

2026-08-05 后端把 region 字节改成了全窗口精确聚合，并在响应里自述
（30.1 实测 `region_byte_source: audit_flow_geo_summary_window_exact`、
`bytes_are_sample_only: false`、`capabilities.byte_accounting_exact: true`），
regions 字节合计 75,093,167 对 `window_bytes` 75,454,736。

所以「一律只报流数」本身也变成了失真，契约随之收紧为**跟随后端自述**：

6. 口径判定不得写死。精确时显示字节，采样时只报流数并打「抽样」徽标，
   后端未表态时按采样处理（保守方向与缺陷成因一致）。
7. 判定必须同时读顶层与 `capabilities` 两处，只读一半会把已精确的数据继续当采样。
8. 流数显示必须用 `window_flow_count`（全窗口），不是 `flow_count`（坐标采样行，
   实测合计 192 对 `window_flow_rows` 31,108）。拿采样流数冒充总量与拿采样字节
   冒充总量是同一类错误。
9. `bytesOf()` 不得把 `bytes` 与 `tx_bytes` 相加。实测每一条都满足
   `bytes == rx_bytes + tx_bytes`，相加等于把上行算两遍（微信消息 2.52MB 被显示成
   4.96MB，https 73.18MB 被显示成 105.78MB），字节合计也就永远对不上摘要。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "files/www/dreamingwrt/static/js/insights-flows.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """抓出一个函数体，避免断言被同名注释满足。"""
    match = re.search(rf"function {name}\(", SOURCE)
    assert match, f"函数不存在：{name}"
    start = SOURCE.index("{", match.end() - 1)
    depth = 0
    for index in range(start, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start : index + 1]
    raise AssertionError(f"函数体未闭合：{name}")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def test_destination_card_never_shows_sampled_geo_bytes() -> None:
    """缺陷本体是把 geo 的采样字节当成用量显示，不是「用了 geo」本身。"""
    metric = _strip_comments(_fn("topItemMetric"))
    # 采样来源的条目必须走流数分支，且必须在字节分支之前拦下。
    assert "__geo_sampled" in metric, "geo 地点条目必须单独判定，不能落进字节分支"
    assert metric.index("__geo_sampled") < metric.index("formatBytes"), (
        "采样判定必须早于 formatBytes，否则采样字节还是会被当成用量显示"
    )
    places = _strip_comments(_fn("destinationTopItems"))
    assert "formatBytes" not in places, "地点榜不得自己格式化字节"
    assert "__geo_sampled" in places, "地点条目必须打上采样标记"


def test_sampling_verdict_follows_backend_not_hardcoded() -> None:
    """采样与否只能由后端自述决定，不许写死成常量。"""
    places = _strip_comments(_fn("destinationTopItems"))
    assert "geoBytesAreSampled()" in places, "口径必须现场问后端，不能假设"
    assert not re.search(r"__geo_sampled\s*:\s*true", places), (
        "不得把 __geo_sampled 写死为 true —— 后端已声明精确时那是另一种失真"
    )
    assert not re.search(r"metric_type\s*:\s*'flow_count'\s*[,}]", places), (
        "排名指标也必须跟随口径，精确时按字节排名"
    )


def test_place_rows_report_window_flow_count_not_sample_rows() -> None:
    """`flow_count` 是坐标采样行数，`window_flow_count` 才是全窗口。"""
    places = _strip_comments(_fn("destinationTopItems"))
    match = re.search(r"const count = firstNumber\(([^)]*)\)", places)
    assert match, "取不到流数取值链"
    chain = match.group(1)
    assert "window_flow_count" in chain, "必须优先用全窗口流数"
    assert chain.index("window_flow_count") < chain.index("region.flow_count"), (
        "window_flow_count 必须排在 flow_count 之前，否则显示的是采样行数"
    )


def test_bytes_reader_does_not_double_count_upload() -> None:
    """实测 bytes == rx + tx，所以 bytes + tx 会把上行算两遍。"""
    body = _strip_comments(_fn("bytesOf"))
    # 缺陷形态：把合计字段（bytes/total_bytes/traffic_bytes）和 tx_bytes 加在一起。
    # `rx_bytes + tx_bytes` 本身是合法的兜底，不能一并禁掉，所以只盯合计字段那条链。
    assert not re.search(
        r"firstNumber\([^)]*item\.(?:bytes|total_bytes|traffic_bytes)[^)]*\)\s*\+\s*firstNumber\(\s*item\.tx_bytes",
        body,
    ), "不得把合计字段与 tx_bytes 相加：bytes 已经是双向合计，再加等于把上行算两遍"
    # 有显式合计时必须直接返回，只有在完全没有合计字段时才用 rx + tx 拼。
    assert re.search(r"if \(total\) return total|total \?", body), (
        "有显式合计时必须直接返回，不再叠加单向计数"
    )


def test_sampled_source_is_labeled_in_the_card_head() -> None:
    """采样数据源不得无标注地渲染，徽标要真的画出来，不能只写在注释里。"""
    card = _strip_comments(_fn("topCard"))
    # `_fn()` 只返回函数体，签名要在整份源码里核对。
    assert re.search(r"function topCard\(\s*title,\s*empty,\s*items,\s*kind,\s*note", SOURCE), (
        "topCard 必须接受口径徽标参数"
    )
    assert "note" in card and "insights-console-count" in card, "徽标必须进入卡片头部"
    note = _strip_comments(_fn("destinationCardNote"))
    assert "geoBytesAreSampled()" in note, "徽标内容必须由后端自述决定"
    assert "抽样" in note, "采样时必须显式标注"
    overview = _strip_comments(_fn("overviewMarkup"))
    assert "destinationCardNote()" in overview, "调用点必须把徽标传进去，否则等于没做"


def test_count_unit_follows_the_actual_dimension() -> None:
    """回退到主机维度时，计数单位不能还写「地区」。"""
    label = _strip_comments(_fn("topCountLabel"))
    assert "destinationTopItems()" in label, "单位必须跟随这一屏真正的维度"
    assert "主机" in label, "主机回退时单位应为「主机」"


def test_destination_card_falls_back_to_hosts_without_geo() -> None:
    card = _strip_comments(_fn("destinationCardItems"))
    assert "destinationTopItems()" in card
    assert "destinationHostTopItems()" in card, "geo 不可用时必须回退主机维度，卡片不能空白"
    host = _strip_comments(_fn("destinationHostTopItems"))
    assert "top_all_count_by_destination" in host, "主机回退仍以摘要为准"
    overview = _strip_comments(_fn("overviewMarkup"))
    assert "destinationCardItems()" in overview
    # 旧缺陷形态：地图有数据就优先用地图的三元回退，混用两种口径。
    assert not re.search(r"destinationItems\.length\s*\?", overview), "不得保留采样优先的三元回退"
    assert "geoDestinationItems" not in overview


def test_sampled_geo_item_builder_is_gone() -> None:
    body = _strip_comments(SOURCE)
    assert "function geoDestinationItems" not in body, "采样列表构造函数必须删除，否则回归只是一行之隔"
    assert "geoDestinationItems(" not in body, "不得残留调用点"


def test_map_still_consumes_geo_points() -> None:
    """只砍列表里的采样字节，不能把地图的数据源一起砍掉。"""
    body = _strip_comments(SOURCE)
    assert body.count("mapPoints()") >= 4, "地图仍须使用 geo 点位渲染"
    assert "function mapDisplayPoints" in body


def test_sampling_flags_are_respected() -> None:
    guard = _fn("geoBytesAreSampled")
    for flag in ("byte_accounting_exact", "exact_window_bytes", "bytes_are_sample_only"):
        assert flag in guard, f"必须尊重后端的精确性标记 {flag}"
    body = _strip_comments(guard)
    # 后端 2026-08-05 把结论放在顶层，只读 capabilities 会漏掉它。
    assert "state.geo || {}" in body or "data.capabilities" in body, (
        "必须同时读顶层与 capabilities 两处"
    )
    assert "region_byte_source" in body or "geo_region_bytes_window_exact" in body, (
        "必须认得后端声明「精确」的字段，否则已精确的数据会被继续当采样"
    )
    # 兜底分支必须是 true（按采样处理），而不是 false（当成精确值直接显示）。
    tail = body.rstrip().rstrip("}").rstrip().rstrip(";").rstrip()
    assert tail.endswith("return true"), (
        "后端未表态时必须按采样处理：把采样字节当总量正是缺陷成因，"
        f"当前兜底为 {tail[-40:]!r}"
    )


def test_map_points_stay_small() -> None:
    """用户 2026-08-04：「流量地图里的点小一点，太大了目前」。

    30.1 实测改后：远端点 10.2 → 6.1px，本机点 20 → 12px。
    这里只钉上界，避免下一次调参又把点放大回去。
    """
    size = _strip_comments(_fn("cyberPointSize"))
    numbers = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", size)]
    assert numbers, "取不到尺寸常量"
    assert max(numbers) <= 12, f"地图点上界不得超过 12px，当前常量：{numbers}"
    # 仍要按权重区分大小，不能退化成固定尺寸。
    assert "Math.sqrt" in size, "点大小仍应按指标归一化"


def test_destination_label_is_a_place() -> None:
    """用户 2026-08-04：目的地要显示「美国洛杉矶」这样的地点，并配国旗。"""
    label = _strip_comments(_fn("topItemName"))
    branch = label[label.index("'destination'") :]
    assert "geoPlaceLabel(item)" in branch, "地点名必须由 geoPlaceLabel() 拼"
    place = _strip_comments(_fn("geoPlaceLabel"))
    assert "country_name" in place and "city_name" in place, "地点名要用国家 + 城市"
    # 香港/新加坡这类城邦两个字段相同，拼出来不能变成「香港香港」。
    assert "local !== country" in place, "国家与城市同名时不得重复拼接"


def test_destination_rows_carry_country_flags() -> None:
    flag = _strip_comments(_fn("countryFlagUrl"))
    assert "/static/images/flags/" in flag, "国旗必须取固件自带的 flags 资源"
    # 只接受两位 ISO 国家码：region_code 之类的行政区代码拼出来是 404。
    assert "[a-z]{2}" in flag, "必须校验两位国家码，否则会拼出不存在的旗帜路径"
    icon = _strip_comments(_fn("topItemIconSrc"))
    assert "countryFlagUrl(item)" in icon


def test_rank_rows_use_real_icon_sources() -> None:
    """应用图标与设备图标都必须来自真实来源，不许前端凭空造。"""
    icon = _strip_comments(_fn("topItemIconSrc"))
    # 应用：后端已给 icon_url / icon_file / icon_key。
    assert "icon_url" in icon and "icon_file" in icon
    # 客户端：走全局共享的设备图库，与仪表盘同一套优先级。
    assert "DWRT_DEVICE_IMAGES" in icon, "设备图标必须复用全局设备图库，不要另造一套"
    assert "resolve" in icon
    # 纯服务条目（https、tcp/21385）不是应用，不许硬塞图标。
    assert "identity_kind" in icon, "service 类条目必须排除，否则会给协议塞上不相干的品牌图"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("insights destination bytes source contract: ok")
