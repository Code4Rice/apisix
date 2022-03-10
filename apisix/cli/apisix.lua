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

local pkg_cpath_org = package.cpath
local pkg_path_org = package.path

local apisix_home = "/usr/local/apisix"
local pkg_cpath = apisix_home .. "/deps/lib64/lua/5.1/?.so;"
                  .. apisix_home .. "/deps/lib/lua/5.1/?.so;"
local pkg_path = apisix_home .. "/deps/share/lua/5.1/?.lua;"


-- 将apisix默认的模块路径和c模块路径添加到全局的搜索路径中
-- modify the load path to load our dependencies
package.cpath = pkg_cpath .. pkg_cpath_org
package.path  = pkg_path .. pkg_path_org

-- pass path to construct the final result
-- 通过引入cli下的env模块来确认整个项目运行的相关环境参数
local env = require("apisix.cli.env")(apisix_home, pkg_cpath_org, pkg_path_org)

-- 引入cli下的ops模块，ops模块中则实现了apisix命令中所有的动作选项
local ops = require("apisix.cli.ops")

-- 具体动作选项执行的入口
ops.execute(env, arg)
