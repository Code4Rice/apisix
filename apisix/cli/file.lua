--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local yaml = require("tinyyaml")
local profile = require("apisix.core.profile")
local util = require("apisix.cli.util")

local pairs = pairs
local type = type
local tonumber = tonumber
local getmetatable = getmetatable
local getenv = os.getenv
local str_gmatch = string.gmatch
local str_find = string.find
local str_sub = string.sub

local _M = {}
local exported_vars


function _M.get_exported_vars()
    return exported_vars
end


-- 如果 line 为空，或者当前 line 最开头的字符为 # 或者 $，返回 false
local function is_empty_yaml_line(line)
    return line == '' or str_find(line, '^%s*$') or str_find(line, '^%s*#')
end


local function tab_is_array(t)
    local count = 0
    for k, v in pairs(t) do
        count = count + 1
    end

    return #t == count
end

-- 遍历入参 conf，如果里面有需要替换的参数，则从环境变量中寻找并匹配
local function resolve_conf_var(conf)
    for key, val in pairs(conf) do
        -- 如果是 table 类型的，则继续 resolve_conf_var
        if type(val) == "table" then
            local ok, err = resolve_conf_var(val)
            if not ok then
                return nil, err
            end

        elseif type(val) == "string" then
            local err
            local var_used = false
            -- we use '${{var}}' because '$var' and '${var}' are taken
            -- by Nginx
            -- 如果存在动态修改的变量，这里拿 - http://${{ETCD_HOST:=localhost}}:2379 为例
            -- 则从环境变量获取，并覆盖

            -- 匹配 ${{}}，所以这里获取到的 var 为 ETCD_HOST:=localhost
            local new_val = val:gsub("%$%{%{%s*([%w_]+[%:%=]?.-)%s*%}%}", function(var)
                -- var： ETCD_HOST:=localhost
                -- 获取 : 和 = 号所在索引 （10， 11）
                local i, j = var:find("%:%=")
                local default
                -- 拼接 default 和 var
                if i and j then
                    default = var:sub(i + 2, #var)
                    default = default:gsub('^%s*(.-)%s*$', '%1')
                    var = var:sub(1, i - 1)
                end
                -- 拼接后 default：localhost var：ETCD_HOST

                -- 从环境变量中获取 var: ETCD_HOST 的内容
                -- 将映射写入 exported_vars 中，后续用的到？
                local v = getenv(var) or default
                if v then
                    if not exported_vars then
                        exported_vars = {}
                    end

                    exported_vars[var] = v
                    var_used = true
                    return v
                end

                err = "failed to handle configuration: " ..
                      "can't find environment variable " .. var
                return ""
            end)

            if err then
                return nil, err
            end

            -- 如果上面有匹配到值，则做一下特殊配置
            if var_used then
                if tonumber(new_val) ~= nil then
                    new_val = tonumber(new_val)
                elseif new_val == "true" then
                    new_val = true
                elseif new_val == "false" then
                    new_val = false
                end
            end

            -- 配置赋值
            conf[key] = new_val
        end
    end

    return true
end


local function tinyyaml_type(t)
    local mt = getmetatable(t)
    if mt then
        return mt.__type
    end
end


local function path_is_multi_type(path, type_val)
    if str_sub(path, 1, 14) == "nginx_config->" and
            (type_val == "number" or type_val == "string") then
        return true
    end

    if path == "apisix->node_listen" and type_val == "number" then
        return true
    end

    if path == "apisix->ssl->listen_port" and type_val == "number" then
        return true
    end

    return false
end

-- 合并配置（把 new_tab 合入 base 中）
local function merge_conf(base, new_tab, ppath)
    ppath = ppath or ""

    for key, val in pairs(new_tab) do
        -- 下面为针对不同类型的一系列赋值过程
        -- 如果目标 val 类型为 table 且无内容，则 base 对应 key 的内容设为 nil
        -- 如果目标 val 类型为 table 且有值，则递归 merge_conf()
        if type(val) == "table" then
            if tinyyaml_type(val) == "null" then
                base[key] = nil

            elseif tab_is_array(val) then
                base[key] = val

            else
                if base[key] == nil then
                    base[key] = {}
                end

                -- 合并子项（子 table）
                local ok, err = merge_conf(
                    base[key],
                    val,
                    ppath == "" and key or ppath .. "->" .. key
                )
                if not ok then
                    return nil, err
                end
            end
        else
            -- 以下为 val 类型不为 table 的场景，直接判断并赋值 base 中即可
            local type_val = type(val)

            if base[key] == nil then
                base[key] = val
            -- 如果目标表中存在对应的 key
            elseif type(base[key]) ~= type_val then
                local path = ppath == "" and key or ppath .. "->" .. key

                -- 判断当前值是否为复合类型
                -- 在 path_is_multi_type() 中有将对应的场景单独列出来判断
                if path_is_multi_type(path, type_val) then
                    base[key] = val
                else
                    return nil, "failed to merge, path[" .. path ..  "] expect: " ..
                                type(base[key]) .. ", but got: " .. type_val
                end
            else
                base[key] = val
            end
        end
    end

    return base
end

-- 读取 yaml 配置
function _M.read_yaml_conf(apisix_home)
    -- 配置 apisix 项目所在地址
    if apisix_home then
        profile.apisix_home = apisix_home .. "/"
    end

    -- 拼接 config-default 配置文件所在路径
    local local_conf_path = profile:yaml_path("config-default")

    -- 读取文件
    local default_conf_yaml, err = util.read_file(local_conf_path)
    if not default_conf_yaml then
        return nil, err
    end

    -- yaml 文件序列化
    local default_conf = yaml.parse(default_conf_yaml)
    if not default_conf then
        return nil, "invalid config-default.yaml file"
    end

    -- 拼接 config 配置文件所在路径
    local_conf_path = profile:yaml_path("config")

    -- 读取文件
    local user_conf_yaml, err = util.read_file(local_conf_path)
    if not user_conf_yaml then
        return nil, err
    end

    local is_empty_file = true
    -- 如果 line 为空，或者当前 line 最开头的字符为 # 或者 $，将 is_empty_file 设为 false？
    for line in str_gmatch(user_conf_yaml .. '\n', '(.-)\r?\n') do
        if not is_empty_yaml_line(line) then
            is_empty_file = false
            break
        end
    end

    if not is_empty_file then
        -- yaml 文件序列化
        local user_conf = yaml.parse(user_conf_yaml)
        if not user_conf then
            return nil, "invalid config.yaml file"
        end


        -- 结合环境变量将 yaml 动态参数初始化
        local ok, err = resolve_conf_var(user_conf)
        if not ok then
            return nil, err
        end

        -- 将 user_conf 内容合入 default_conf 里
        ok, err = merge_conf(default_conf, user_conf)
        if not ok then
            return nil, err
        end
    end

    return default_conf
end


return _M
