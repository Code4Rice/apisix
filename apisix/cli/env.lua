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

local require = require
local util = require("apisix.cli.util")

local pcall = pcall
local error = error
local exit = os.exit
local stderr = io.stderr
local str_find = string.find
local arg = arg
local package = package
local tonumber = tonumber

return function (apisix_home, pkg_cpath_org, pkg_path_org)
    -- 获取内核设置的同时可打开文件描述符的最大值
    local res, err = util.execute_cmd("ulimit -n")
    if not res then
        error("failed to exec ulimit cmd \'ulimit -n \', err: " .. err)
    end
    local ulimit = tonumber(util.trim(res))
    if not ulimit then
        error("failed to fetch current maximum number of open file descriptors")
    end

    -- only for developer, use current folder as working space
    local is_root_path = false
    local script_path = arg[0]

    -- 看是否脚本执行的cli/apisix.lua是否是以./这样的相对路径开头的
    if script_path:sub(1, 2) == './' then
        apisix_home = util.trim(util.execute_cmd("pwd"))
        if not apisix_home then
            error("failed to fetch current path")
        end

        -- determine whether the current path is under the "/root" folder.
        -- "/root/" is the root folder flag.

        -- 判断项目是否在系统的根目录下
        if str_find(apisix_home .. "/", '/root/', nil, true) == 1 then
            is_root_path = true
        end

        local pkg_cpath = apisix_home .. "/deps/lib64/lua/5.1/?.so;"
                          .. apisix_home .. "/deps/lib/lua/5.1/?.so;"

        local pkg_path = apisix_home .. "/?/init.lua;"
                         .. apisix_home .. "/deps/share/lua/5.1/?/init.lua;"
                         .. apisix_home .. "/deps/share/lua/5.1/?.lua;;"

        -- 根据确认的项目根目录路径设置lua模块路径以及c模块路径，并将路径放入全局路径中
        -- 不清楚为什么不把默认路径的拼接逻辑放到此代码块中
        package.cpath = pkg_cpath .. package.cpath
        package.path  = pkg_path .. package.path
    end

    do
        -- 通过pcall执行require table.new来判断LuaJIT版本是否大于2.1（因为LuaJIT在2.1才引入table.new反法)
        local ok = pcall(require, "table.new")
        if not ok then
            -- 通过pcall来判断引入cjson模块是否成功
            -- 如果LuaJIT版本不大于2.1且引入cjson模块成功，需要删除lua本身的cjson模块，而是使用OpenResty中的cjson模块
            local ok, json = pcall(require, "cjson")
            if ok and json then
                stderr:write("please remove the cjson library in Lua, it may "
                            .. "conflict with the cjson library in openresty. "
                            .. "\n luarocks remove lua-cjson\n")
                exit(1)
            end
        end
    end

    -- OpenResty真正的启动执行命令和参数
    local openresty_args = [[openresty -p ]] .. apisix_home .. [[ -c ]]
                           .. apisix_home .. [[/conf/nginx.conf]]

    -- 所需etcd的最小版本
    local min_etcd_version = "3.4.0"

    --  env.lua主要确定的环境变量返回并传入到ops中
    return {
        apisix_home = apisix_home,
        is_root_path = is_root_path,
        openresty_args = openresty_args,
        pkg_cpath_org = pkg_cpath_org,
        pkg_path_org = pkg_path_org,
        min_etcd_version = min_etcd_version,
        ulimit = ulimit,
    }
end
