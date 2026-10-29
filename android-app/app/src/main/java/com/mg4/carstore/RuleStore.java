package com.mg4.carstore;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * 规则引擎 —— 与 Python 版 proxy_server.py 行为保持一致。
 *
 * store_rules.json 结构:
 * {
 *   "serve": [ {"host":..., "path_prefix":..., "file":...} ],
 *   "patch": [ {"host":..., "method":..., "path_prefix":..., "set": {...}} ]
 * }
 */
public class RuleStore {

    public static class ServeRule {
        public String host;
        public String pathPrefix;
        public String pathSuffix;
        public String file;
    }

    public static class PatchRule {
        public String host;
        public String method;
        public String pathPrefix;
        public JSONObject set;
    }

    public final List<ServeRule> serve = new ArrayList<>();
    public final List<PatchRule> patch = new ArrayList<>();

    /** 全局生效的域名 (DNS 劫持用) */
    public final List<String> hijackDomains = new ArrayList<>();

    public void load(JSONObject root) {
        serve.clear();
        patch.clear();
        hijackDomains.clear();

        JSONArray s = root.optJSONArray("serve");
        if (s != null) {
            for (int i = 0; i < s.length(); i++) {
                JSONObject o = s.optJSONObject(i);
                if (o == null) continue;
                ServeRule r = new ServeRule();
                r.host = o.optString("host", null);
                r.pathPrefix = o.optString("path_prefix", null);
                r.pathSuffix = o.optString("path_suffix", null);
                r.file = o.optString("file", null);
                serve.add(r);
            }
        }

        JSONArray p = root.optJSONArray("patch");
        if (p != null) {
            for (int i = 0; i < p.length(); i++) {
                JSONObject o = p.optJSONObject(i);
                if (o == null) continue;
                PatchRule r = new PatchRule();
                r.host = o.optString("host", null);
                r.method = o.optString("method", null);
                r.pathPrefix = o.optString("path_prefix", null);
                r.set = o.optJSONObject("set");
                patch.add(r);
            }
        }

        // 收集需要劫持的域名
        for (ServeRule r : serve) {
            if (r.host != null && !hijackDomains.contains(r.host)) {
                hijackDomains.add(r.host);
            }
        }
        for (PatchRule r : patch) {
            if (r.host != null && !hijackDomains.contains(r.host)) {
                hijackDomains.add(r.host);
            }
        }
    }

    // ------------------------------------------------------------ 规则匹配

    public ServeRule matchServe(String host, String path) {
        for (ServeRule r : serve) {
            if (r.host != null && !r.host.equals(host)) continue;
            if (r.pathPrefix != null && !path.startsWith(r.pathPrefix)) continue;
            if (r.pathSuffix != null) {
                String p = path;
                int q = p.indexOf('?');
                if (q >= 0) p = p.substring(0, q);
                if (!p.endsWith(r.pathSuffix)) continue;
            }
            return r;
        }
        return null;
    }

    public PatchRule matchPatch(String host, String path, String method) {
        for (PatchRule r : patch) {
            if (r.host != null && !r.host.equals(host)) continue;
            if (r.method != null && !r.method.equalsIgnoreCase(method)) continue;
            if (r.pathPrefix != null && !path.startsWith(r.pathPrefix)) continue;
            return r;
        }
        return null;
    }

    // ------------------------------------------------------- 点路径 get/set

    /** 取值, 第二个返回表示是否存在。 */
    public static Object getPath(JSONObject root, String path) {
        String[] segs = path.split("\\.");
        Object cur = root;
        for (String seg : segs) {
            if (!(cur instanceof JSONObject)) return null;
            JSONObject o = (JSONObject) cur;
            if (!o.has(seg)) return null;
            cur = o.opt(seg);
        }
        return cur;
    }

    /** 写值, 成功返回 true。 */
    public static boolean setPath(JSONObject root, String path, Object value) {
        String[] segs = path.split("\\.");
        Object cur = root;
        for (int i = 0; i < segs.length - 1; i++) {
            if (!(cur instanceof JSONObject)) return false;
            JSONObject o = (JSONObject) cur;
            if (!o.has(segs[i])) return false;
            cur = o.opt(segs[i]);
        }
        if (!(cur instanceof JSONObject)) return false;
        JSONObject o = (JSONObject) cur;
        String last = segs[segs.length - 1];
        if (!o.has(last)) return false;
        try {
            o.put(last, value);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
