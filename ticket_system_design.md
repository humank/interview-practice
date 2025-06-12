# 高併發搶票系統設計 - AWS 雲架構方案

## 場景描述

台北大巨蛋舉辦 MLB 與中華職棒明星對抗賽，全場可售票數為 45,000 張。系統需處理開賣瞬間數十萬到上百萬人同時搶票的極端高併發場景。

基本流程：
1. 用戶選擇日期
2. 選擇座位區域（內野、外野、樓層區域）
3. 選擇張數（最多 8 張）
4. 送出購票申請
5. 系統確認是否搶票成功
6. 成功則進入付款流程，失敗則返回選票頁面

## 系統挑戰

1. **極端高併發**：開賣瞬間可能有上百萬人同時搶票
2. **資源競爭**：同一座位可能被多人同時選中
3. **系統穩定性**：需確保系統不崩潰
4. **防刷票**：防止黃牛使用程式大量搶票
5. **用戶體驗**：提供即時反饋，減少等待時間

## AWS 雲架構設計

### 整體架構

![AWS 搶票系統架構](https://via.placeholder.com/800x500.png?text=AWS+Ticket+System+Architecture)

```
用戶 → CloudFront → Route 53 → WAF → 
  → ALB → ECS/Fargate (前端服務) → 
    → ALB → ECS/Fargate (API 服務) → 
      → ElastiCache (Redis) / DynamoDB → 
        → SQS/Kinesis → 
          → Lambda/ECS (訂單處理) → 
            → Aurora/RDS
```

### 關鍵 AWS 服務選型

1. **邊緣服務與安全**
   - **CloudFront**：全球內容分發，減少延遲
   - **Route 53**：DNS 服務，地理路由策略
   - **WAF**：防止 DDoS 攻擊和惡意爬蟲
   - **Shield**：提供額外 DDoS 防護

2. **計算與容器服務**
   - **ECS/Fargate**：無需管理伺服器的容器服務
   - **Auto Scaling**：根據流量自動擴展容器數量
   - **Lambda**：無伺服器計算，處理突發流量

3. **數據存儲與緩存**
   - **ElastiCache (Redis)**：高性能分布式緩存
   - **DynamoDB**：低延遲 NoSQL 數據庫，自動擴展
   - **Aurora**：高性能關係型數據庫，處理訂單數據

4. **消息與流處理**
   - **SQS**：可靠的消息隊列服務
   - **Kinesis**：實時數據流處理
   - **EventBridge**：事件驅動架構

5. **監控與運維**
   - **CloudWatch**：監控和告警
   - **X-Ray**：分布式追蹤
   - **CloudTrail**：API 調用審計

## 核心技術實現

### 1. 流量控制與削峰填谷

利用 AWS 服務實現流量控制，而非僅依賴應用程式：

```
CloudFront → API Gateway → SQS → Lambda/ECS
```

**實現方式：**

1. **CloudFront 配置**：
   - 設置緩存策略，減輕源站壓力
   - 配置地理限制，防止國外機器人攻擊

2. **API Gateway 限流**：
   ```json
   {
     "usagePlan": {
       "name": "TicketingThrottling",
       "throttle": {
         "burstLimit": 5000,
         "rateLimit": 1000
       },
       "quota": {
         "limit": 50000,
         "period": "DAY"
       }
     }
   }
   ```

3. **SQS 虛擬候場**：
   ```java
   // 將用戶請求發送到 SQS 隊列
   public String enqueueUser(String userId) {
       SendMessageRequest request = SendMessageRequest.builder()
           .queueUrl(queueUrl)
           .messageBody(userId)
           .messageGroupId("ticketing")  // 使用 FIFO 隊列
           .messageDeduplicationId(UUID.randomUUID().toString())
           .build();
       
       SendMessageResponse response = sqsClient.sendMessage(request);
       return response.messageId();
   }
   ```

### 2. 座位庫存管理

使用 DynamoDB 和 ElastiCache 實現高性能座位庫存：

**DynamoDB 表設計**：

```
Table: Seats
- PK: seat_id (string)
- SK: event_id (string)
- status: available/locked/sold (string)
- lock_expiration: timestamp
- version: number (用於樂觀鎖)
```

**座位鎖定實現**：

```java
// 使用 DynamoDB 條件表達式實現原子操作
public boolean lockSeat(String seatId, String eventId, String orderId) {
    try {
        Map<String, AttributeValue> expressionValues = new HashMap<>();
        expressionValues.put(":status", AttributeValue.builder().s("available").build());
        expressionValues.put(":newStatus", AttributeValue.builder().s("locked").build());
        expressionValues.put(":orderId", AttributeValue.builder().s(orderId).build());
        expressionValues.put(":expiration", 
            AttributeValue.builder().n(String.valueOf(System.currentTimeMillis() + 300000)).build());
        
        UpdateItemRequest request = UpdateItemRequest.builder()
            .tableName("Seats")
            .key(Map.of(
                "seat_id", AttributeValue.builder().s(seatId).build(),
                "event_id", AttributeValue.builder().s(eventId).build()
            ))
            .updateExpression("SET status = :newStatus, lock_by = :orderId, " +
                             "lock_expiration = :expiration")
            .conditionExpression("status = :status")
            .expressionAttributeValues(expressionValues)
            .build();
        
        dynamoDbClient.updateItem(request);
        return true;
    } catch (ConditionalCheckFailedException e) {
        // 座位已被鎖定或售出
        return false;
    }
}
```

**ElastiCache 座位狀態快照**：

```java
// 使用 Redis Bitmap 存儲座位狀態
@Service
public class SeatStatusService {
    
    @Autowired
    private JedisPool jedisPool;
    
    public boolean isSeatAvailable(String eventId, int seatId) {
        try (Jedis jedis = jedisPool.getResource()) {
            return jedis.getbit("event:" + eventId + ":seats", seatId) == false;
        }
    }
    
    public boolean markSeatAsLocked(String eventId, int seatId) {
        try (Jedis jedis = jedisPool.getResource()) {
            // 使用 Lua 腳本確保原子性
            String script = 
                "if redis.call('getbit', KEYS[1], ARGV[1]) == 0 then " +
                "    redis.call('setbit', KEYS[1], ARGV[1], 1); " +
                "    return 1; " +
                "else " +
                "    return 0; " +
                "end";
            
            Object result = jedis.eval(script, 
                Collections.singletonList("event:" + eventId + ":seats"), 
                Collections.singletonList(String.valueOf(seatId)));
            
            return Integer.valueOf(1).equals(result);
        }
    }
}
```

### 3. 訂單處理流水線

使用 AWS 服務構建高效訂單處理流水線：

```
API Gateway → Kinesis Data Streams → Lambda → DynamoDB/Aurora
```

**Kinesis 生產者**：

```java
// 將訂單請求發送到 Kinesis
public void submitOrder(TicketOrder order) {
    PutRecordRequest request = PutRecordRequest.builder()
        .streamName("ticket-orders-stream")
        .partitionKey(order.getUserId())
        .data(SdkBytes.fromUtf8String(objectMapper.writeValueAsString(order)))
        .build();
    
    kinesisClient.putRecord(request);
}
```

**Lambda 消費者**：

```java
// Lambda 函數處理訂單
public class OrderProcessorHandler implements RequestHandler<KinesisEvent, Void> {
    
    @Override
    public Void handleRequest(KinesisEvent event, Context context) {
        for (KinesisEvent.KinesisEventRecord record : event.getRecords()) {
            String data = new String(
                record.getKinesis().getData().array(),
                StandardCharsets.UTF_8
            );
            
            TicketOrder order = objectMapper.readValue(data, TicketOrder.class);
            
            // 1. 驗證座位狀態
            boolean seatsAvailable = validateSeats(order.getSeats());
            
            if (seatsAvailable) {
                // 2. 鎖定座位
                lockSeats(order.getSeats());
                
                // 3. 創建訂單
                createOrder(order);
                
                // 4. 發送確認通知
                sendNotification(order.getUserId(), "訂單已確認");
            } else {
                // 發送失敗通知
                sendNotification(order.getUserId(), "座位已被搶購");
            }
        }
        return null;
    }
}
```

### 4. 虛擬候場系統

使用 AWS 服務實現虛擬候場，控制進入選票頁面的流量：

```
CloudFront → Lambda@Edge → API Gateway → DynamoDB
```

**Lambda@Edge 實現**：

```javascript
// Lambda@Edge 函數控制用戶進入
exports.handler = async (event) => {
    const request = event.Records[0].cf.request;
    const headers = request.headers;
    
    // 獲取用戶 ID (從 Cookie 或查詢參數)
    const userId = getUserId(headers);
    
    if (!userId) {
        // 重定向到登錄頁面
        return {
            status: '302',
            statusDescription: 'Found',
            headers: {
                'location': [{
                    key: 'Location',
                    value: '/login?redirect=' + request.uri
                }]
            }
        };
    }
    
    // 檢查用戶是否可以進入選票頁面
    const canEnter = await checkUserAccess(userId);
    
    if (canEnter) {
        // 允許訪問
        return request;
    } else {
        // 重定向到等待頁面
        return {
            status: '302',
            statusDescription: 'Found',
            headers: {
                'location': [{
                    key: 'Location',
                    value: '/waiting-room?userId=' + userId
                }]
            }
        };
    }
};

async function checkUserAccess(userId) {
    // 調用 API Gateway 檢查用戶狀態
    // 實際實現會使用 AWS SDK 或 HTTPS 請求
}
```

**DynamoDB 候場表**：

```
Table: WaitingRoom
- PK: user_id (string)
- position: number
- join_time: timestamp
- status: waiting/ready/expired (string)
```

### 5. 防刷票與安全機制

結合 AWS WAF 和應用層防護：

**WAF 規則配置**：

```json
{
  "Name": "TicketingProtection",
  "Rules": [
    {
      "Name": "RateLimitRule",
      "Priority": 1,
      "Action": { "Block": {} },
      "Statement": {
        "RateBasedStatement": {
          "Limit": 100,
          "AggregateKeyType": "IP",
          "ScopeDownStatement": {
            "ByteMatchStatement": {
              "FieldToMatch": { "UriPath": {} },
              "PositionalConstraint": "STARTS_WITH",
              "SearchString": "/api/tickets",
              "TextTransformations": [
                { "Priority": 0, "Type": "NONE" }
              ]
            }
          }
        }
      }
    },
    {
      "Name": "BlockBadBots",
      "Priority": 2,
      "Action": { "Block": {} },
      "Statement": {
        "ByteMatchStatement": {
          "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
          "PositionalConstraint": "CONTAINS",
          "SearchString": "bot",
          "TextTransformations": [
            { "Priority": 0, "Type": "LOWERCASE" }
          ]
        }
      }
    }
  ]
}
```

**Cognito 用戶認證**：

```java
// 使用 Cognito 進行用戶認證
public AuthenticationResult authenticateUser(String username, String password) {
    try {
        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        
        AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
            .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
            .clientId(cognitoClientId)
            .userPoolId(userPoolId)
            .authParameters(authParams)
            .build();
        
        AdminInitiateAuthResponse response = cognitoClient.adminInitiateAuth(authRequest);
        return response.authenticationResult();
    } catch (NotAuthorizedException e) {
        throw new InvalidCredentialsException("用戶名或密碼錯誤");
    }
}
```

## AWS 服務配置與優化

### 1. 自動擴展配置

**ECS 服務自動擴展**：

```json
{
  "scalingPolicies": [
    {
      "policyName": "cpu-tracking-scaling",
      "policyType": "TargetTrackingScaling",
      "targetTrackingScalingPolicyConfiguration": {
        "targetValue": 70.0,
        "predefinedMetricSpecification": {
          "predefinedMetricType": "ECSServiceAverageCPUUtilization"
        },
        "scaleOutCooldown": 60,
        "scaleInCooldown": 300
      }
    },
    {
      "policyName": "sqs-queue-depth-scaling",
      "policyType": "TargetTrackingScaling",
      "targetTrackingScalingPolicyConfiguration": {
        "targetValue": 10.0,
        "customizedMetricSpecification": {
          "metricName": "ApproximateNumberOfMessagesVisible",
          "namespace": "AWS/SQS",
          "dimensions": [
            {
              "name": "QueueName",
              "value": "ticketing-queue"
            }
          ],
          "statistic": "Average"
        },
        "scaleOutCooldown": 30,
        "scaleInCooldown": 300
      }
    }
  ]
}
```

### 2. ElastiCache 集群配置

**Redis 集群設置**：

```json
{
  "CacheClusterId": "ticketing-cache",
  "Engine": "redis",
  "CacheNodeType": "cache.r6g.xlarge",
  "NumCacheNodes": 1,
  "ReplicationGroupId": "ticketing-redis",
  "AutomaticFailoverEnabled": true,
  "CacheParameterGroupName": "default.redis6.x",
  "EngineVersion": "6.x",
  "PreferredMaintenanceWindow": "sun:05:00-sun:06:00",
  "SnapshotRetentionLimit": 7,
  "NumNodeGroups": 3,
  "ReplicasPerNodeGroup": 2
}
```

### 3. DynamoDB 容量配置

**DynamoDB 表配置**：

```json
{
  "TableName": "Seats",
  "BillingMode": "PAY_PER_REQUEST",
  "DeletionProtectionEnabled": true,
  "GlobalSecondaryIndexes": [
    {
      "IndexName": "EventIndex",
      "KeySchema": [
        {
          "AttributeName": "event_id",
          "KeyType": "HASH"
        },
        {
          "AttributeName": "status",
          "KeyType": "RANGE"
        }
      ],
      "Projection": {
        "ProjectionType": "ALL"
      }
    }
  ],
  "SSESpecification": {
    "Enabled": true,
    "SSEType": "KMS"
  },
  "StreamSpecification": {
    "StreamEnabled": true,
    "StreamViewType": "NEW_AND_OLD_IMAGES"
  }
}
```

### 4. CloudFront 配置

**CloudFront 分發設置**：

```json
{
  "Origins": [
    {
      "Id": "ticketing-alb",
      "DomainName": "ticketing-alb-123456789.ap-northeast-1.elb.amazonaws.com",
      "CustomOriginConfig": {
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "https-only",
        "OriginSSLProtocols": ["TLSv1.2"]
      }
    }
  ],
  "DefaultCacheBehavior": {
    "TargetOriginId": "ticketing-alb",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
    "CachedMethods": ["GET", "HEAD", "OPTIONS"],
    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
    "OriginRequestPolicyId": "216adef6-5c7f-47e4-b989-5492eafa07d3",
    "LambdaFunctionAssociations": [
      {
        "EventType": "viewer-request",
        "LambdaFunctionARN": "arn:aws:lambda:us-east-1:123456789012:function:waiting-room:1"
      }
    ]
  },
  "PriceClass": "PriceClass_200",
  "Enabled": true,
  "WebACLId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/TicketingProtection/abcdef12-3456-7890-abcd-ef1234567890"
}
```

## 系統容量規劃

### 1. 流量估算

- 假設開賣瞬間有 100 萬用戶同時訪問
- 每個用戶平均產生 10 次請求
- 峰值 QPS = 1,000,000 × 10 ÷ 60 ≈ 166,667 QPS

### 2. AWS 資源配置

- **CloudFront**：全球分發，無需特別容量規劃
- **API Gateway**：設置 10,000 RPS 的限流
- **ECS/Fargate**：
  - 前端服務：50-100 個任務
  - API 服務：100-200 個任務
  - 訂單處理：50-100 個任務
- **ElastiCache**：
  - 3 個分片，每個分片 2 個副本
  - 節點類型：cache.r6g.xlarge
- **DynamoDB**：按需容量模式
- **SQS/Kinesis**：
  - SQS：標準隊列，無限擴展
  - Kinesis：10-20 個分片

### 3. 成本優化

- **預留實例**：對於基礎負載使用預留實例
- **Spot 實例**：對於可中斷的工作負載使用 Spot 實例
- **Auto Scaling**：根據實際流量自動調整資源
- **CloudFront 緩存優化**：提高緩存命中率
- **DynamoDB 按需容量**：僅在高峰期支付高容量費用

### 4. 監控與告警

**CloudWatch 儀表板**：

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/ApiGateway", "Count", "ApiName", "TicketingAPI", {"stat": "Sum"}]
        ],
        "period": 60,
        "title": "API 請求數"
      }
    },
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/ApiGateway", "Latency", "ApiName", "TicketingAPI", {"stat": "Average"}]
        ],
        "period": 60,
        "title": "API 延遲"
      }
    },
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "ticketing-queue"]
        ],
        "period": 60,
        "title": "SQS 隊列深度"
      }
    },
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", "Seats"],
          ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", "Seats"]
        ],
        "period": 60,
        "title": "DynamoDB 容量消耗"
      }
    }
  ]
}
```

**CloudWatch 告警**：

```json
{
  "alarms": [
    {
      "alarmName": "ApiGateway5xxErrors",
      "alarmDescription": "API Gateway 5xx 錯誤率超過閾值",
      "metricName": "5XXError",
      "namespace": "AWS/ApiGateway",
      "dimensions": [
        {
          "name": "ApiName",
          "value": "TicketingAPI"
        }
      ],
      "period": 60,
      "evaluationPeriods": 1,
      "threshold": 5,
      "comparisonOperator": "GreaterThanThreshold",
      "statistic": "Sum",
      "treatMissingData": "notBreaching"
    },
    {
      "alarmName": "DynamoDBThrottling",
      "alarmDescription": "DynamoDB 節流事件",
      "metricName": "ThrottledRequests",
      "namespace": "AWS/DynamoDB",
      "dimensions": [
        {
          "name": "TableName",
          "value": "Seats"
        }
      ],
      "period": 60,
      "evaluationPeriods": 1,
      "threshold": 1,
      "comparisonOperator": "GreaterThanThreshold",
      "statistic": "Sum",
      "treatMissingData": "notBreaching"
    }
  ]
}
```

## 災難恢復與高可用性

### 1. 多可用區部署

- 所有服務跨至少 3 個可用區部署
- 數據庫和緩存服務啟用多可用區配置

### 2. 跨區域備份

- DynamoDB 全局表
- S3 跨區域複製
- Aurora 全局數據庫

### 3. 故障轉移策略

- Route 53 健康檢查和故障轉移路由
- 自動化故障檢測和恢復流程

## 總結

利用 AWS 雲服務構建高併發搶票系統的核心優勢：

1. **彈性擴展**：AWS 服務可根據流量自動擴展，應對突發流量
2. **分布式架構**：利用雲原生服務分散負載，避免單點故障
3. **邊緣計算**：CloudFront 和 Lambda@Edge 將處理邏輯推向離用戶最近的位置
4. **無服務器架構**：減少基礎設施管理負擔，專注業務邏輯
5. **托管服務**：利用 AWS 托管服務減少自行開發的複雜性

通過將大部分高併發挑戰交給 AWS 雲服務處理，應用程式可以專注於核心業務邏輯，提供更穩定、可靠的搶票體驗。