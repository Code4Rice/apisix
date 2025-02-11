---
title: Consumer
---

<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

For an API gateway, it is usually possible to identify the type of the requester by using things like their request domain name and client IP address. A gateway like APISIX can then filter these requests using [Plugins](./plugin.md) and forward it to the specified [Upstream](./upstream.md).

But this level of depth can be insufficient in some occasions.

![consumer-who](../../../assets/images/consumer-who.png)

An API gateway should know who the consumer of the API is to configure different rules for different consumers.

This is where the Consumer construct comes in APISIX. The fields are defined below.

| Field    | Required | Description                                                                                                                                                                                      |
| -------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| username | Yes      | Name of the consumer.                                                                                                                                                                                   |
| plugins  | No       | Plugin configuration of the Consumer. It has the highest priority: Consumer > Route > Service. For specific Plugin configurations, refer the [Plugins](./plugin.md) section. |

The process of identifying a Consumer in APISIX is described below:

![consumer-internal](../../../assets/images/consumer-internal.png)

1. The first step is Authentication. This is achieved by Authentication Plugins like [key-auth](../plugins/key-auth.md) and [JWT](../plugins/jwt-auth.md).
2. After authenticating, you can obtain the `id` of the Consumer. This `id` will be the unique identifier of a Consumer.
3. The configurations like Plugins and Upstream bound to the Consumer are then executed.

Consumers are useful when you have different consumers requesting the same API and you need to execute different Plugin and Upstream configurations based on the consumer. These need to be used in conjunction with the user authentication system.

Refer the documentation for the [key-auth](../plugins/key-auth.md) authentication Plugin to further understand the concept of a Consumer.

The example below shows how you can enable a Plugin for a specific Consumer.

```shell
# Create a Consumer, specify the authentication plugin key-auth, and enable the specific plugin limit-count
$ curl http://127.0.0.1:9080/apisix/admin/consumers -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "username": "jack",
    "plugins": {
        "key-auth": {
            "key": "auth-one"
        },
        "limit-count": {
            "count": 2,
            "time_window": 60,
            "rejected_code": 503,
            "key": "remote_addr"
        }
    }
}'

# Create a Router, set routing rules and enable plugin configuration
$ curl http://127.0.0.1:9080/apisix/admin/routes/1 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "plugins": {
        "key-auth": {}
    },
    "upstream": {
        "nodes": {
            "127.0.0.1:1980": 1
        },
        "type": "roundrobin"
    },
    "uri": "/hello"
}'

# Send a test request, the first two return to normal, did not reach the speed limit threshold
$ curl http://127.0.0.1:9080/hello -H 'apikey: auth-one' -I
...

$ curl http://127.0.0.1:9080/hello -H 'apikey: auth-one' -I
...

# The third test returns 503 and the request is restricted
$ curl http://127.0.0.1:9080/hello -H 'apikey: auth-one' -I
HTTP/1.1 503 Service Temporarily Unavailable
...

```

We can use the [consumer-restriction](../plugins/consumer-restriction.md) Plugin to restrict our user "Jack" from accessing the API.

```shell
# Add Jack to the blacklist
$ curl http://127.0.0.1:9080/apisix/admin/routes/1 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "plugins": {
        "key-auth": {},
        "consumer-restriction": {
            "blacklist": [
                "jack"
            ]
        }
    },
    "upstream": {
        "nodes": {
            "127.0.0.1:1980": 1
        },
        "type": "roundrobin"
    },
    "uri": "/hello"
}'

# Repeated tests, all return 403; Jack is forbidden to access this API
$ curl http://127.0.0.1:9080/hello -H 'apikey: auth-one' -I
HTTP/1.1 403
...

```
