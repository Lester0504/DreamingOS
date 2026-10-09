(() => {
  'use strict';
  async function request(route, params = {}, method = 'GET') {
    const response = await window.DWRT_REQUEST.fetch(`/api/v1/nas${route}${method === 'GET' ? '?' + new URLSearchParams(params) : ''}`, {
      method, credentials: 'same-origin', cache: 'no-store', ...(method === 'POST' ? {headers:{'Content-Type':'application/json'}, body:JSON.stringify(params)} : {})
    });
    let payload;
    try { payload = await response.json(); } catch (_) { throw new Error(`响应无效（HTTP ${response.status}）`); }
    const data = payload.data || payload;
    if (!response.ok || data.error || payload.code >= 4000) {
      const reasons = {metadata_conflict:'资料已在其他窗口修改。当前草稿已保留，请复制需要的内容，关闭后重新打开最新资料。',invalid_metadata:'资料格式不正确，请检查年份、季集、评分或拍摄时间。',revision_conflict:'播放队列已在其他窗口改变，请重新读取后再保存。',invalid_queue:'队列含重复、已移出媒体库或不属于本应用的内容。',invalid_cover:'封面必须来自当前集合中的媒体。',package_not_installed:'尚未安装 NAS 应用。',service_unavailable:'NAS 服务未运行或无法连接。',storage_unavailable:'数据盘不可用，请选择已挂载的可写目录。',dependency_missing:'此功能的可选组件尚未安装。',job_running:'已有文件任务在运行，请等待完成。',source_unavailable:'源目录不可用。',library_conflict:'此目录已在媒体库中。',operation_unsupported:'当前组件不支持此操作。',unsupported_url:'此引擎不支持该下载地址。',engine_rejected:'下载引擎拒绝了请求，请检查地址和任务状态。',destination_unavailable:'下载目录不可写或已离线。',bad_credentials:'下载引擎凭据无效，请在原插件中检查。',engine_unreachable:'无法连接下载引擎。'};
      throw Object.assign(new Error(response.status===401?'会话已过期，请重新登录。':response.status===403?'当前账号没有此操作权限。':reasons[data.error]||data.message||`请求失败（HTTP ${response.status}）`),{code:data.error,status:response.status,data});
    }
    return data;
  }
  window.DWRT_NAS = Object.freeze({request, post:(route, params) => request(route, params, 'POST')});
})();
