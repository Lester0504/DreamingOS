#!/usr/bin/env python3
"""洞察—流量地图弧线的聚合粒度契约。

用户报告：进入洞察—流量后，弧线像机关枪一样批量开花，例如"到日本的抛物线会在上方
平移出很多条一样的线"。

根因（已在浏览器里量出来）：后端在 GeoIP City 库命中时给出**城市级** `lat` / `lon`
（`webd_insights_add_geo_city_json()` 会写 `geo_precision: "city"` 与城市坐标），
同一个国家的多座城市因此各自成为一条独立路由。这些路由共用同一个起点，弯曲度又是
固定的 ±0.31，于是在世界地图缩放下终点彼此只差几像素——实测大阪与名古屋 6px、
东京与名古屋 11px、五条弧的最小端点间距 6px。五条同形状同曲率的弧叠起来，就是用户
看到的那把扇子。

修法不是改曲率，也不是限制条数，而是**按地图真正能分辨的粒度聚合**：世界视图同一
国家一条弧，中国视图同一省份一条。城市级细节留给列表与 tooltip。

这里守四件事：

1. 聚合发生在 `mapRouteItems()`，三个消费方（SVG 兜底层、ECharts 矢量层、
   概览小地图）共用同一份结果，不能只修其中一个。
2. 分组键必须是行政区划标识而不是高精度坐标。退回坐标时粒度必须放粗（整度），
   保留三位小数等于"几乎不合并"，就是这个 bug 的来源。
3. 合并后的弧端点要落在该行政区划的标准坐标上，否则弧会指向"先到的那座城市"。
4. 多个地点并成一条弧时标签必须升到聚合粒度并标注地点数量，写"日本 东京"会让另外
   四座城市的流量看起来都发生在东京。
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
JS = (WWW / "static/js/insights-flows.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    start = JS.index(f"function {name}(")
    depth = 0
    for index in range(JS.index("{", start), len(JS)):
        if JS[index] == "{":
            depth += 1
        elif JS[index] == "}":
            depth -= 1
            if depth == 0:
                return JS[start : index + 1]
    raise AssertionError(f"unterminated {name}")


def test_aggregation_is_shared_by_every_consumer() -> None:
    assert "function aggregateMapRoutes(routes, scope)" in JS
    items = _fn("mapRouteItems")
    assert "aggregateMapRoutes(" in items, "聚合必须发生在 mapRouteItems()，三个消费方共用"
    # 三个消费方都只经由 mapRouteItems() 取路由
    assert JS.count("mapRouteItems()") >= 3


def test_group_key_uses_administrative_scope_not_fine_coordinates() -> None:
    key = _fn("routeScopeKey")
    assert "provinceCodeOf(point)" in key, "中国视图必须按省份聚合"
    assert "countryCodeOf(point)" in key, "世界视图必须按国家聚合"
    # 退回坐标时粒度必须放粗。toFixed(3) 是最初的缺陷；toFixed(0)（约 1 度）是第二次
    # 的不足——世界视图下 1 度只有几个像素，实测 24 条相邻路由仍留下 9 条重合弧。
    # 现在按视图分桶，见 test_coordinate_fallback_granularity_is_screen_scale。
    assert "toFixed(3)" not in key, "坐标退路不得保留三位小数，那等于不合并"
    assert "toFixed(0)" not in key, "1 度粒度在世界视图下仍然几乎不合并"


def test_merged_arc_endpoint_snaps_to_the_scope_coordinate() -> None:
    assert "function aggregatedEndpoint(point)" in JS
    endpoint = _fn("aggregatedEndpoint")
    assert "CHINA_PROVINCE_COORDINATES" in endpoint
    assert "COUNTRY_COORDINATES" in endpoint
    routes = JS[JS.index("function cyberMapRoutes(role)") :]
    routes = routes[: routes.index("function aggregatedEndpoint")]
    assert "mergedCount" in routes, "只有真正合并过的弧才改端点"
    assert "aggregatedEndpoint(route.to)" in routes


def test_merged_label_rises_to_the_scope_and_states_the_count() -> None:
    label = _fn("aggregatedRouteLabel")
    assert "mergedCount > 1" in label, "只合并过才改标签"
    assert "个地点" in label, "必须标注被合并的地点数量"
    for field in ("region_name", "country_name"):
        assert field in label, field


def test_curveness_stays_a_single_value_per_direction() -> None:
    # 不允许"给每条弧不同曲率"这种绕开聚合的糊法：那会把重复弧变成故意的扇形
    item = _fn("cyberRouteSeriesItem")
    curveness = re.findall(r"curveness:\s*([^\n,]+)", item)
    assert curveness, "路由样式必须显式给出曲率"
    for value in curveness:
        assert "index" not in value and "random" not in value, f"曲率不得随条目变化: {value}"


def test_series_level_curveness_does_not_fight_the_item_level() -> None:
    """三层弧的系列级曲率必须交给数据项，否则三层天然错位、放大"开花"观感。

    历史写法是系列级 0.28、数据项级 ±0.31，两者不一致，glow / routes / pulse
    三层不完全重合。曲率只留数据项一处。
    """
    assert "curveness: 0.28" not in JS, "系列级 curveness 必须删除，只保留数据项级"
    assert JS.count("curveness: inbound ? -0.31 : 0.31") == 1, "数据项级曲率应当是唯一来源"


def test_map_render_is_coalesced_and_throttled() -> None:
    """实时推送每 250ms 一条，而更新动画 420ms：不去重就会把多轮未完成的动画叠在屏上。

    裸 `requestAnimationFrame` 既拿不到句柄也无法跳过重复排队，是"机关枪开花"在
    时间维度上的成因。这里要求调度器持有句柄、有最小间隔，并且保留最后一次。
    """
    sched = _fn("scheduleMapRender")
    assert "requestAnimationFrame" in sched
    assert "mapRender.frame" in sched, "必须持有 rAF 句柄才能去重"
    assert re.search(r"if \(mapRender\.frame\) return;", sched), "已排队时必须直接返回"
    assert "MAP_RENDER_MIN_INTERVAL" in sched, "推送触发的重绘必须节流"
    assert "setTimeout" in sched, "节流必须保留最后一次（trailing），不能丢掉最终状态"
    interval = re.search(r"const MAP_RENDER_MIN_INTERVAL = (\d+)", JS)
    assert interval and int(interval.group(1)) >= 1000, (
        f"最小间隔要与 420ms 更新动画拉开差距: {interval and interval.group(1)}"
    )


def test_unchanged_topology_skips_set_option() -> None:
    """多数推送不改变地图拓扑，重复 setOption 只会重放动画。"""
    assert "function cyberMapSignature" in JS
    render = _fn("renderCyberMapContainer")
    assert "__dwrtCyberSignature" in render, "必须记住上一次的签名"
    assert re.search(r"container\.__dwrtCyberSignature === signature", render), "签名未变必须跳过 setOption"
    # 更新动画必须为 0，否则重绘频率一旦高于动画时长，副本叠加会复现
    assert "animationDurationUpdate: 0" in JS, "实时更新路径不得再放更新动画"
    assert "animateEntrance" in JS, "入场动画只保留给首绘与作用域切换"


def test_scope_switch_keeps_cache_and_does_not_run_full_refresh() -> None:
    """切换世界/中国只需要 geo，走整页 refresh 会等上 insights_summary 那个 30s 请求。"""
    assert "geoByScope" in JS, "必须按作用域分别缓存 geo"
    assert "function refreshMapOnly" in JS, "作用域切换必须有只取地图的路径"
    switch = re.search(r"data-map-scope[\s\S]{0,700}?\}\)\);", JS)
    assert switch, "找不到作用域切换的事件绑定"
    body = switch.group(0)
    assert "state.geo = null" not in body, "切换不得丢弃已有数据"
    assert "refreshMapOnly()" in body, "切换只应触发地图取数"
    assert re.search(r"render\(\);", body), "必须先渲染出高亮，再异步取数"


def test_missing_risk_fields_are_not_reported_as_zero() -> None:
    """后端没给字段时显示 0，等于把"未提供"谎报成"真实值为零"。"""
    counts = _fn("summaryCounts")
    assert "supported" in counts, "必须区分「值为 0」与「字段缺失」"
    assert "concerning" in counts, "后端拼写是 concerning，只读 concern 会永远为空"
    markup = _fn("summaryMarkup")
    assert "后端未提供" in markup, "字段全缺时必须明说，不能渲染成 0"


def test_coordinate_fallback_granularity_is_screen_scale() -> None:
    """国家码缺失时退回坐标分桶，桶宽必须是"屏幕能分辨"的量级。

    历史写法是 toFixed(0)，约 1 度。世界视图下 1 度只有几个像素，实测 24 条相邻城市
    路由仍留下 9 条几乎重合、等间距的弧，就是用户说的"一条线被平移复制多次"。
    """
    key = _fn("routeScopeKey")
    assert "toFixed(0)" not in key, "1 度粒度在世界视图下仍然几乎不合并"
    assert "COORD_BUCKET_WORLD" in key and "COORD_BUCKET_CHINA" in key, "分桶角度必须按视图区分"
    world = re.search(r"const COORD_BUCKET_WORLD = ([\d.]+)", JS)
    china = re.search(r"const COORD_BUCKET_CHINA = ([\d.]+)", JS)
    assert world and float(world.group(1)) >= 8, f"世界视图桶宽过窄: {world and world.group(1)}"
    assert china and float(china.group(1)) >= 2, f"中国视图桶宽过窄: {china and china.group(1)}"


def test_visually_overlapping_arcs_are_merged_after_bucketing() -> None:
    """分桶只看绝对坐标，桶边界两侧的两点仍可能在屏幕上重合。

    曲率相同的两条重合弧看起来就是"同一条线被平移"，所以合并之后必须再按角距收一次。
    """
    assert "function mergeAdjacentRoutes" in JS
    agg = _fn("aggregateMapRoutes")
    assert "mergeAdjacentRoutes" in agg, "聚合的返回值必须再经过角距去重"
    merge = _fn("mergeAdjacentRoutes")
    assert "ARC_MIN_SEPARATION" in merge, "去重阈值必须是显式常量"
    assert "direction" in merge, "只有同向的弧才能合并，进出方向必须分开"
    # 跨 ±180 的经度差必须取较短一侧，否则太平洋两岸会被当成相距 350 度
    gap = _fn("angularGap")
    assert "360" in gap and "180" in gap, "经度环绕必须处理，否则跨太平洋的弧判定失效"


def test_merged_label_never_claims_a_single_city() -> None:
    """坐标退路上没有国家名，此时也不能只挂第一座城市的名字。"""
    label = _fn("aggregatedRouteLabel")
    assert "个地点" in label
    assert "附近" in label, "无行政区划名时必须表明这是附近多个地点的合并值"


def test_arc_label_names_the_remote_end_not_the_router() -> None:
    """inbound 的远端在 `from`，`to` 是本机 WAN。

    用 30.1 只读凭据实测：9 条 inbound 全部被标成「本机 · 116.113.39.208」，
    新加坡/塞舌尔/保加利亚/美国的来源信息全丢了。三处取名都必须走远端。
    """
    assert "function remoteEndpointOf" in JS, "必须有统一的远端取端函数"
    remote = _fn("remoteEndpointOf")
    assert "is_local" in remote and "role === 'local'" in remote, "判定本机要认全部三种标记"
    # 聚合、角距合并、单条弧三处取名都不得直接用 to
    agg = _fn("aggregateMapRoutes")
    assert "aggregatedRouteLabel(remoteEndpointOf(existing)" in agg, "聚合取名必须用远端"
    merge = _fn("mergeAdjacentRoutes")
    assert "aggregatedRouteLabel(remoteEndpointOf(near)" in merge, "角距合并取名必须用远端"
    routes = _fn("cyberMapRoutes")
    assert "mapPointTitle(remoteEndpointOf(route))" in routes, "未合并的单条弧也必须以远端命名"


def test_local_endpoint_never_snaps_to_a_country_centroid() -> None:
    """本机与国内目的地同属 CN。

    若本机也被吸附到中国中心点，弧两端会重合并被 coordinatesEqual() 整条丢掉，
    国内流量就从图上消失；实测还会让出向弧的起点从路由器跳到 (104.20, 35.86)。
    """
    endpoint = _fn("aggregatedEndpoint")
    guard = endpoint[: endpoint.index("state.mapScope")] if "state.mapScope" in endpoint else endpoint
    assert "return null" in guard, "本机必须在吸附之前提前返回"
    assert "is_local" in guard and "role === 'local'" in guard, "本机判定要认全部三种标记"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("insights map route aggregation contract: ok")
